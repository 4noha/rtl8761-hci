# SMP design (rtlhci/smp.py)

Status: implemented and tested **only against software** (`rtlhci.fake.FakeSmpPeer` over
`FakeController`). Nothing here has been run against a real controller or a real peer. The
behaviour of any particular real device is unknown.

Reference: Bluetooth Core Spec Vol 3 Part H (Security Manager), Vol 4 Part E (HCI LE
encryption commands/events). Cross-checked against Linux `net/bluetooth/smp.c` for byte order.

## Files

| file | role |
|---|---|
| `rtlhci/smp.py` | SMP manager: PDUs, per-link state machine, method selection, key distribution, encryption start, timer |
| `rtlhci/smp_crypto.py` | AES-128, AES-CMAC, e/c1/s1/ah/f4/f5/f6/g2/h6/h7, P-256 (keygen, point validation, ECDH). `cryptography` if importable, else pure Python (`RTLHCI_PURE_CRYPTO=1` forces it) |
| `rtlhci/hci.py` | + LE_Start_Encryption / LTK Request (Neg) Reply, Encryption Change / Key Refresh / LE LTK Request parsing, `le_conns` (role, peer address), `bd_addr`, `tick_handlers` |
| `rtlhci/fake.py` | + `FakeSmpPeer` (independent SMP peer, both roles, fault knobs), LE encryption emulation in `FakeController` |
| `tests/test_smp_crypto.py` | spec sample data (both backends) |
| `tests/test_smp.py` | end-to-end flows, failure paths, method table, fuzz |
| `tests/smp_harness.py` | host ↔ fake controller ↔ fake peer wiring |

## Layering and threading

```
Hci.pump() ── ACL ──> L2cap.cid_handlers[0x0006] ──> Smp._on_pdu ──> per-handle _Session
          └─ events ─> Hci.handlers ──> Smp._on_event (LTK Request, Encryption Change, Disconnect)
          └─ end ────> Hci.tick_handlers ──> Smp.tick(): 30 s timer + deferred HCI commands
```

PDU and event handlers never call `Hci.command()` (that would nest a synchronous command wait
inside `read_event`). `LE_Start_Encryption` and the LTK replies are queued and issued from
`tick()` at the end of `pump()`. L2CAP sends (ACL) are allowed from handlers.

Every PDU handler runs inside `try/except`. A `SmpFail(reason)` becomes Pairing Failed(reason).
Any other exception counts in `Smp.errors` and becomes Pairing Failed(Unspecified). Tests assert
`errors == 0`.

## State machine (per LE connection handle)

```
                    central: pair()                      peripheral: pair()
 IDLE ──────────────> WAIT_RSP                IDLE ───────> WAIT_REQ (Security Request sent)
                         │ Pairing Response                    │ Pairing Request
  peripheral: Pairing Request ─────────────────────────────────┘
                         ▼
        legacy ──────────┴────────── secure connections
          │                              │
   WAIT_CONFIRM  (Mconfirm/Sconfirm)  WAIT_PUBKEY (Public Key exchange, ECDH)
          │                              │ JW/NC: Cb ; Passkey: 20 × (Cai,Cbi,Nai,Nbi)
   WAIT_RANDOM   (Mrand/Srand, c1)    WAIT_CONFIRM ⇄ WAIT_RANDOM
          │ STK = s1(TK,Srand,Mrand)     │ (NC: g2 → user confirm)
          │                           WAIT_DHKEY  (f5 → MacKey/LTK, f6 → Ea/Eb)
          └──────────────┬───────────────┘
                         ▼
                   WAIT_ENCRYPT   central: LE_Start_Encryption(STK|LTK, EDIV=0, Rand=0)
                         │        peripheral: LE LTK Request → LTK Request Reply
                         │ Encryption Change (status 0, on)
                         ▼
                    KEY_DIST     responder sends first, then initiator. Order per side:
                         │       EncInfo, CentralIdent (legacy only), IdentityInfo,
                         ▼       IdentityAddrInfo, SigningInfo
                       DONE  → PairingResult(success) [+ Bond if both set Bonding]

 any active state ── Pairing Failed rx ──────────> FAILED (remote=True, nothing sent)
                  ── bad/unexpected PDU ─────────> FAILED (Pairing Failed sent)
                  ── 30 s without a PDU queued ──> TIMEOUT (nothing sent, SMP silent on link)
                  ── Disconnection Complete ─────> session dropped, result "disconnected"
```

Validation rules:

| input | answer |
|---|---|
| empty PDU | Pairing Failed 0x0A Invalid Parameters |
| unknown / RFU code (0x00, ≥0x0F) | 0x07 Command Not Supported |
| length ≠ table length (3.3) | 0x0A |
| Pairing Request to a central, Security Request to a peripheral | 0x07 |
| known code not expected in the current state | 0x08 Unspecified Reason |
| IO cap > 4, OOB flag > 1, max key size > 16 | 0x0A |
| max key size < 7 (or < `min_key_size`) | 0x06 Encryption Key Size |
| responder sets key-dist bits we did not request | 0x0A |
| OOB requested (SC: either side; legacy: both) | 0x02 OOB Not Available |
| MITM required and only Just Works possible; `sc_only` and peer is legacy | 0x03 Authentication Requirements |
| peripheral with `accept_pairing=False` | 0x05 Pairing Not Supported |
| confirm mismatch (legacy c1, SC Cb, passkey round) | 0x04 Confirm Value Failed |
| public key not on P-256 / reflected public key / Ea or Eb mismatch | 0x0B DHKey Check Failed |
| user rejects numeric comparison | 0x0C |
| passkey entry cancelled / out of range | 0x01 |
| key PDU on an unencrypted link or out of order | 0x08 |
| Pairing Failed received (any length) | abort, never answered |
| anything after TIMEOUT | ignored (3.4) |

Two deliberate leniencies:
1. RFU bits in AuthReq and key distribution are ignored on receipt, as 3.5.1 requires.
2. Key-distribution PDUs that arrive *before* our Encryption Change event (events and ACL use
   different USB endpoints, so the order is not guaranteed) are held (max 6) and replayed once
   encryption is on. They are still fully validated on replay.

Method selection: Table 2.8 (`smp._METHOD_TABLE`), JW when neither side sets MITM. The fake peer
derives the same thing from rules rather than a table, and a test compares the two over all
5×5×SC×MITM combinations. The displaying side generates its passkey during feature exchange,
before it sends anything. The inputting side asks the delegate when it first needs the value.

## Crypto verification (spec sample data)

| function | source | backends |
|---|---|---|
| AES-128 | FIPS-197 C.1 | pure + cryptography |
| AES-CMAC | RFC 4493 (4 vectors) | pure + cryptography |
| c1 | Vol 3 Part H 2.2.3 example | both |
| s1 | Vol 3 Part H 2.2.4 example | both |
| ah, f4, f5, f6, g2, h6 | Vol 3 Part H Appendix D | both |
| P-256 public key / ECDH | debug key pair (2.3.5.6.1) + 2 P-256 sample data sets + debug self-DH | both |
| invalid points | off-curve, zero, all-0xFF, wrong length → `InvalidPublicKey` | both |

The vectors were taken from the Linux kernel's self-test copies of the spec tables (smp.c,
selftest.c), not from the PDF directly. h7 has no vector test (it is only used for CTKD, which
is not implemented).

## Test matrix (tests/test_smp.py, all over fake HCI/ACL with 27-byte peer fragments)

| flow | host central | host peripheral |
|---|---|---|
| legacy Just Works (+ full key dist order check) | ✓ | ✓ |
| SC Just Works (no EncInfo on air) | ✓ | ✓ |
| SC Numeric Comparison (values equal both sides) | ✓ | ✓ |
| Passkey legacy/SC × host types / host displays / both type (20 rounds) | ✓ | ✓ |
| key size 7 (masking), no bonding | ✓ | |
| Security Request → peer starts pairing | | ✓ |
| re-encryption from bond: SC LTK and legacy LTK (LE_Start_Encryption) | ✓ | |
| re-encryption: LTK Request lookup by EDIV/Rand, negative reply on mismatch (legacy) | | ✓ |
| wrong confirm (legacy, SC) | ✓ | ✓ |
| passkey mismatch (legacy, SC) | ✓ | |
| NC rejected locally | ✓ | ✓ |
| NC rejected by peer | ✓ | |
| DHKey check corrupt, invalid public key | ✓ | ✓ |
| reflected public key | ✓ | |
| 30 s timeout (+ silence afterwards) | ✓ | ✓ |
| timer reset per queued PDU | ✓ | |
| remote Pairing Failed | ✓ | |
| 17 malformed / out-of-order / unsupported PDUs → exact reason | ✓ | |
| MITM unsatisfiable, passkey cancelled | ✓ | |
| SC-only vs legacy peer, pairing disabled, peer key size 6 | | ✓ |
| LL encryption failures (LTK mismatch → MIC disconnect, key missing) | ✓ | |
| key dist out of order, early key dist buffering | ✓ | |
| keypress notifications (valid + invalid type) | | ✓ |
| BR/EDR SMP refused; LE CID on BR/EDR handle ignored | ✓ | |
| random PDU fuzz (software only, 60 seeds per role): no exception, only well-formed output | ✓ | ✓ |

## Open risks

1. **Real hardware is not fuzzed by default.** Some peripherals only accept pairing inside a
   short window, and unexpected input may make them drop the link or require a power cycle. So:
   * **No fuzzing or fault injection (`FakeSmpPeer`-style corrupt confirms, malformed PDUs,
     timeouts) against real hardware.** The fuzz test targets this host stack only.
   * The first real pairing against a new device should be a single plain attempt (SC Just
     Works or legacy JW, depending on what the peer advertises), with `--btsnoop` on.
   * Several peer quirks observed on hardware are selectable via `SMP_*` environment variables
     (`SMP_F4_XCROSS`, `SMP_EAGER_ENCRYPT`, `SMP_DIST_LTK`, `SMP_KEYS_FIRST`).
2. Real controllers (RTL8761BU firmware) may order Encryption Change, Number Of Completed
   Packets and the first key PDU differently from the fake. That is why early key PDUs are
   buffered, but other orderings could still show up.
3. The own address is assumed to be public (address type 0, `read_bd_addr`). Using a random or
   resolvable address would change c1/f5/f6 inputs and needs Enhanced Connection Complete
   local-RPA handling.
4. Bonds live in memory only. Peers using RPAs are keyed by connection address (no IRK
   resolution yet).
5. Synchronous delegate: user input blocks `pump()`. Over the 30 s timer that is fine for
   tests, but a real UI needs an async reply path.
6. Not implemented: OOB, CTKD / BR/EDR SMP, signed writes, Repeated Attempts back-off,
   SC-only key-size policy beyond `min_key_size`.
7. The crypto was validated against published vectors. It is not constant-time (pure-Python
   P-256), which is acceptable for a test tool but not for anything security-critical.
