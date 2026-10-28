# rtl8761-hci — userspace Bluetooth HCI stack for RTL8761 (UB500 / UB500 Plus)

A pure-Python (pyusb/libusb) host stack that talks to the controller directly: the host owns
the USB interface and implements the protocol itself. No BlueZ, no IOBluetooth.

```
rtlhci/usb_transport.py  libusb transport (EP0 cmd / intr-IN evt / bulk ACL), detach+claim with diagnostics
rtlhci/hci.py            HCI packets, event parser, sync commands, flow control, LE scan, inquiry, ACL credits
rtlhci/acl.py            ACL header, L2CAP fragment/reassembly, L2CAP mux + basic signaling (echo/info/reject)
rtlhci/rtl.py            Realtek vendor cmds (0xFC61/0xFC6D/0xFC66/0xFC20), epatch v1/v2 parser, fw download
rtlhci/btsnoop.py        btsnoop v1 / H4 capture writer (rotation, drops counter), hooked at the transport boundary
rtlhci/smp.py            LE Security Manager: legacy + Secure Connections pairing, key distribution, encryption start
rtlhci/smp_crypto.py     AES-128/CMAC, c1/s1/ah/f4/f5/f6/g2/h6/h7, P-256 ECDH (cryptography pkg or pure-Python fallback)
rtlhci/fake.py           software RTL8761BU controller + fake pyusb device + fake SMP peer (for tests / --fake)
selftest.py              hardware self-test
docs/SMP-DESIGN.md       SMP state machine, test matrix, open risks
firmware/                optional: put rtl_bt blobs here (not included; see "Firmware")
tests/                   pytest, no hardware needed (tests/data/example.btsnoop = simulated SC pairing capture)
```

## Setup

```sh
# macOS
brew install libusb
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/pip install cryptography      # optional: faster crypto backend (pure-Python fallback otherwise)
.venv/bin/pytest -q                      # 147 tests (1 skipped without `cryptography`), no hardware needed
.venv/bin/python selftest.py all --fake  # dry run of the whole flow
```

## Running against the dongle (step by step; stop at the first NG)

```sh
.venv/bin/python selftest.py list                 # enumerate only, no claim. Expect 2357:0604
.venv/bin/python selftest.py probe                # detach/claim/release, prints every step
sudo .venv/bin/python selftest.py probe           # only if the above says ACCESS/BUSY: tells "permission" vs "owned"
.venv/bin/python selftest.py init --skip-fw       # ROM-only bring-up: vendor reads + reset/version/addr
.venv/bin/python selftest.py init                 # with Realtek firmware download
.venv/bin/python selftest.py le-scan --seconds 10
.venv/bin/python selftest.py inquiry --seconds 10
```

Every run writes `selftest-<timestamp>.log` with every HCI packet and USB step. Send that log
back when something fails. Add `--btsnoop capture.btsnoop` to every hardware run as well (see below).

## btsnoop capture (Wireshark / btmon)

```sh
.venv/bin/python selftest.py init --btsnoop capture.btsnoop                    # one file
.venv/bin/python selftest.py le-scan --btsnoop cap.btsnoop --btsnoop-max-mb 50  # rotate: cap.btsnoop.1 .2 .3
```

In code: `UsbTransport(dev, snoop=BtSnoopWriter("x.btsnoop"))` (or `open_first(..., snoop=...)`,
`FakeTransport(ctl, snoop=...)`). Format: btsnoop v1, datalink 1002 (HCI UART/H4: type byte + packet),
flag bit0 = direction (0 sent / 1 received), bit1 = command/event, microsecond timestamps.
The capture point is the transport tx/rx boundary only: commands after a successful EP0 write,
events and ACL after USB reassembly (one record per complete HCI packet). Every record is flushed,
so a crash leaves a readable file. Write errors never stop the stack; they are counted in `drops`
(the cumulative drops field of the next record). Rotation renames `PATH` → `PATH.1` → … (keep 3).

Open it with:
* **Wireshark**: File → Open (it detects btsnoop). Useful filters: `btsmp`, `bthci_cmd`, `bthci_evt`,
  `btl2cap.cid == 0x0006`. Command line: `tshark -r capture.btsnoop -Y btsmp -V`.
* **btmon** (BlueZ, on Linux): `btmon -r capture.btsnoop`.
* Without either tool: `python tests/btsnoop_check.py capture.btsnoop` (independent validator + dump).

`tests/data/example.btsnoop` is a *simulated* LE Secure Connections Numeric Comparison pairing
between this stack and the fake peer (regenerate with `python tests/make_example_btsnoop.py`).
It was checked with the validator in `tests/btsnoop_check.py` only. Wireshark/btmon were not
installed on the build box, so it has not been opened in them yet.

Expected on a healthy UB500 (from Linux logs): `examining hci_ver=0a hci_rev=000b lmp_ver=0a
lmp_subver=8761`, `rom_version` 1, key_id 0, download of ~30 KB in ~120 fragments, then
`fw version 0xdfc6d922`.

## Firmware

`rtl8761bu_fw.bin` (44484 B) and `rtl8761bu_config.bin` (6 B) from linux-firmware
`rtl_bt/`, hashes in `firmware/SHA256SUMS`. The epatch is v1 ("Realtech"), project id 14
(8761B), 2 patches for chip ids 1/2, fw_version 0xdfc6d922. Use `--skip-fw` to never load it;
`--fw-dir` to point elsewhere. If the controller already runs patched firmware, the loader sends
0xFC66 (drop fw) once like Linux, then retries; if still unknown it assumes no upload is needed.
Firmware lives in RAM: unplugging the dongle reverts it to ROM.

## macOS driver-claim caveat (unverified until the dongle is plugged in)

On macOS, libusb can only use the interface if no kernel-side client holds it.
Two outcomes are possible and both are handled:

1. **Nobody owns it** (plausible: recent macOS ships no driver for third-party Realtek BT
   dongles). `probe` passes and everything runs on the Mac directly.
2. **Apple's Bluetooth USB transport (bluetoothd / IOBluetooth) owns it.** `probe` fails with
   `LIBUSB_ERROR_ACCESS` (-3) or `LIBUSB_ERROR_BUSY` (-6) at `detach_kernel_driver` or
   `claim_interface`, and the error shows every step plus hints. libusb ≥ 1.0.25 can detach on
   macOS only as root or with the `com.apple.vm.device-access` entitlement. To see who owns it:
   `ioreg -p IOUSB -l -w0 | grep -A30 -i 'UB500\|8761'`.

Do not use kext changes, SIP changes or `nvram bluetoothHostControllerSwitchBehavior` for
this. Use one of the fallbacks instead:

* **Fallback A: Linux box.** Plug the dongle into it, then
  `sudo systemctl stop bluetooth`, then
  `echo -n "<bus-port>:1.0" | sudo tee /sys/bus/usb/drivers/btusb/unbind` (and `:1.1`),
  or blacklist `btusb`. Add a udev rule for 2357:0604 or run with sudo. The same code runs there.
* **Fallback B: Linux VM on the Mac** (UTM / Parallels / VMware Fusion) with USB passthrough
  of 2357:0604. The hypervisor takes the device away from macOS. Then apply Fallback A inside
  the VM.
* Capture and offline analysis can stay on the Mac either way. The stack does not depend on
  where the logs are read.

## SMP (pairing)

```python
from rtlhci.smp import Smp, SmpConfig, PairingDelegate, IO
smp = Smp(hci, l2cap, SmpConfig(io_cap=IO.DISPLAY_YES_NO, mitm=True), MyDelegate())
smp.pair(handle)            # central: Pairing Request; peripheral: Security Request
hci.pump()                  # PDUs are handled in pump(); HCI encryption commands run from its tick
smp.results[handle]         # PairingResult(success, reason, sc, method, key_size, keys...)
smp.encrypt(handle)         # later: re-encrypt from the stored bond (central)
smp.save_bonds("bonds.json")        # mode 0600; merges on load
smp.load_bonds("bonds.json")
smp.pairing_blocked_for(peer)       # seconds left of the Repeated Attempts back-off
```

Status:
* LE legacy pairing (Just Works, Passkey Entry) and LE Secure Connections (Just Works, Numeric
  Comparison, Passkey Entry), on both central and peripheral. Key distribution (LTK+EDIV/Rand,
  IRK + identity address, CSRK). LE_Start_Encryption / LTK Request reply. 30 s SMP timer.
  Strict PDU validation: malformed or out-of-order input gets Pairing Failed and never raises.
* The crypto matches the spec sample data (c1, s1, ah, f4, f5, f6, g2, h6, P-256 ECDH, debug keys)
  on both the pure-Python backend and the `cryptography` backend.
* Bond storage: `smp.bonds` (in memory) plus `save_bonds()` / `load_bonds()` (JSON, mode 0600).
* Repeated Attempts (Core 3.4): `SmpConfig(repeated_attempts_limit=N,
  repeated_attempts_backoff_s=S)` refuses new pairings for S seconds after N consecutive
  failures with the same peer (disabled by default).
* Not implemented: OOB (answered with OOB Not Available), cross-transport key derivation
  (BR/EDR SMP on CID 0x0007 is refused with Pairing Not Supported), RPA generation/resolution,
  signed writes using the CSRK. The own address is assumed to be the public address.
* All of this is tested only against `FakeSmpPeer` (an independent software peer). Real-device
  behaviour varies; several quirks found on hardware are selectable with `SMP_*` environment
  variables (see `docs/SMP-DESIGN.md`). Do not fuzz hardware you do not own or have permission
  to test.

## Status / not done yet

* Hardware coverage is limited to one RTL8761BU dongle. The fake controller models the vendor
  bring-up and public traces, not every RTL8761 variant.
* No SCO/isochronous (interface 1), no ATT/GATT, no L2CAP connection-oriented channels
  (they are refused with "PSM not supported"). `L2cap.cid_handlers` is the hook for ATT (0x0004).
* Single-threaded polling model (`Hci.pump`). Move to a reader thread or async if latency
  matters.

## Firmware

The Realtek firmware/config blobs are **not** included in this repository. Obtain them from
`linux-firmware` (package `linux-firmware`, files `rtl_bt/rtl8761bu_fw.bin` and
`rtl_bt/rtl8761bu_config.bin`) and place them in `firmware/`. The loader can be skipped with
`--skip-fw` if the controller already runs patched firmware.

The vendor command sequence and the epatch container format were implemented from the publicly
documented behaviour and from observing traffic on hardware; no Linux source file is bundled.

## Licence

MIT — see `LICENSE`. The firmware blobs you supply are covered by their own licences
(Realtek / linux-firmware).

## Responsible use

This is a research tool for hardware you own. It drives the controller directly, bypasses the
OS Bluetooth stack, and can transmit arbitrary HCI traffic. Depending on what you send, it can
break pairing, disrupt other devices, or violate local radio regulations. Use it on your own
equipment and at your own risk.
