#!/usr/bin/env python3
"""Hardware self-test for an RTL8761 dongle (run on the machine the dongle is plugged into).

Stages (each one implies the ones before it, except `list`):
  list      enumerate BT-looking USB devices, no claim (safe)
  probe     open + detach/claim + release, print full diagnostics
  init      probe + Realtek setup (fw download unless --skip-fw) + HCI reset/version/addr/buffers
  le-scan   init + LE active scan for --seconds
  inquiry   init + BR/EDR inquiry for --seconds
  all       init + le-scan + inquiry

--fake runs everything against the software controller model (no USB at all).
A log with every HCI packet is written to ./selftest-<timestamp>.log.
--btsnoop PATH additionally writes every HCI packet (H4, btsnoop v1) for Wireshark / btmon -r.
"""
from __future__ import annotations

import argparse
import datetime as dt
import logging
import os
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rtlhci.hci import Hci  # noqa: E402
from rtlhci.rtl import RtlSetup  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def setup_logging(verbose: bool) -> str:
    path = os.path.join(os.getcwd(), f"selftest-{dt.datetime.now():%Y%m%d-%H%M%S}.log")
    logging.basicConfig(level=logging.DEBUG, filename=path,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    con = logging.StreamHandler()
    con.setLevel(logging.DEBUG if verbose else logging.INFO)
    con.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logging.getLogger().addHandler(con)
    return path


def cmd_list() -> int:
    import usb.core
    from rtlhci.usb_transport import KNOWN_IDS, find_bt_devices
    try:
        devs = find_bt_devices()
    except usb.core.NoBackendError:
        print("NG: libusb backend not found. macOS: `brew install libusb`; Linux: apt install libusb-1.0-0")
        return 2
    if not devs:
        print("no Bluetooth-class USB device found")
        return 1
    for d in devs:
        print(f"{d.idVendor:04x}:{d.idProduct:04x} bus={getattr(d, 'bus', '?')} "
              f"addr={getattr(d, 'address', '?')} {KNOWN_IDS.get((d.idVendor, d.idProduct), '(unknown model)')}")
    return 0


def open_snoop(args):
    if not args.btsnoop:
        return None
    from rtlhci.btsnoop import BtSnoopWriter
    mb = args.btsnoop_max_mb
    return BtSnoopWriter(args.btsnoop, max_bytes=int(mb * 1024 * 1024) if mb else None)


def open_transport(args, snoop=None):
    if args.fake:
        from rtlhci.fake import FakeController, FakeTransport
        return FakeTransport(FakeController(), snoop=snoop)
    from rtlhci.usb_transport import open_first
    vid = int(args.vid, 16) if args.vid else None
    pid = int(args.pid, 16) if args.pid else None
    return open_first(vid, pid, detach=not args.no_detach, snoop=snoop)


def decode_state(val: bytes) -> str:
    """EdgeSystemState: [4..7]=FW, [8..11]=platform, [12..15]=boot, [17]=mode, [18]=accepting."""
    if len(val) < 19:
        return f"short state ({len(val)}B)"
    fw = val[4:5].hex() + "." + val[5:8].hex()
    return (f"fw={fw} platform={int.from_bytes(val[8:12], 'big')} "
            f"boot={int.from_bytes(val[12:16], 'big')} mode={val[17]} accepting={val[18]}")


def poll_state(h, att, value_handle: int) -> None:
    """Read EdgeSystemState at a fixed interval and log every change (read-only)."""
    seconds = float(os.environ.get("POLL_S", "120"))
    interval = float(os.environ.get("POLL_EVERY", "1.0"))
    print(f"polling 0x{value_handle:04x} for {seconds:.0f}s every {interval:.1f}s ...")
    start = time.monotonic()
    end = start + seconds
    last = None
    polls = changes = 0
    while time.monotonic() < end:
        tick = time.monotonic()
        try:
            val = att.read(value_handle)
        except Exception as exc:
            print(f"+{tick - start:7.2f}s  read error: {exc}")
            val = None
        if val is not None:
            polls += 1
            if val != last:
                changes += 1
                ts = tick - start
                print(f"+{ts:7.2f}s  {val.hex()}  {decode_state(val)}")
                last = val
        wait = interval - (time.monotonic() - tick)
        if wait > 0:
            time.sleep(wait)
    print(f"  polls={polls} changes={changes}")


def subscribe_and_listen(h, att, cu: str, value_handle: int) -> int:
    """Write 01 00 to the CCCD (the only write we ever do) and print notifications."""
    cccd = value_handle + 1
    try:                       # find the real CCCD (0x2902) if the layout differs
        for hh, hu in att.find_info(value_handle, min(value_handle + 3, 0xFFFF)):
            print(f"  descriptor h={hh:04x} uuid={hu}")
            if hu == "0x2902":
                cccd = hh
    except Exception as exc:
        print(f"  find_info failed: {exc}")
    print(f"subscribe cccd=0x{cccd:04x} ({cu})")
    try:
        att.subscribe(cccd)
        print("  write acknowledged")
    except TimeoutError:
        # the device is known to swallow some writes; keep listening anyway
        print("  write not acknowledged; listening anyway")
    except Exception as exc:
        print(f"  subscribe failed: {exc}")
        return 0
    secs = float(os.environ.get("NOTIFY_S", "15"))
    print(f"  listening {secs:.0f}s ...")
    end = time.monotonic() + secs
    count = 0
    while time.monotonic() < end:
        h.pump(100)
        while att.notify:
            hn, val = att.notify.pop(0)
            count += 1
            print(f"  notify h={hn:04x} len={len(val)} {val.hex()}")
            if cu.endswith("7831"):
                print(f"    state {decode_state(val)}")
    print(f"  notifications: {count}")
    return count


def explore_gatt(h, l2, handle, read_all=True):
    """Read-only GATT exploration: services, characteristics and (optionally) every
    readable value. Never writes -- no CCCD, no commands."""
    from rtlhci.att import AttClient
    att = AttClient(h, l2, handle)
    if os.environ.get("ATT_MTU", "0") == "1":
        try:
            print(f"MTU: {att.exchange_mtu(247)}")
            for _ in range(5):        # let the device settle after the MTU change
                h.pump(100)
        except Exception as exc:
            print(f"MTU exchange failed: {exc}")
    svcs = att.read_by_group()
    seen = set()
    uniq = []
    for row in svcs:
        if row[:2] in seen:
            continue
        seen.add(row[:2])
        uniq.append(row)
    svcs = uniq
    print(f"services: {len(svcs)}")
    found = []
    for s, e, u in svcs:
        print(f"  service {s:04x}-{e:04x} {u}")
        try:
            chars = att.read_by_type(s, e)
        except Exception as exc:
            print(f"    read_by_type failed: {exc}")
            # fall back to a plain handle walk (read-only)
            try:
                handles = att.find_info(s, e)
            except Exception as exc2:
                print(f"    find_info failed: {exc2}")
                continue
            for hh, hu in handles:
                print(f"    info h={hh:04x} uuid={hu}")
                try:
                    val = att.read(hh)
                    print(f"      value = {val.hex()}")
                except Exception as exc3:
                    print(f"      read failed: {exc3}")
            continue
        for ch, props, vh, cu in chars:
            print(f"    char h={ch:04x} props=0x{props:02x} val={vh:04x} {cu}")
            found.append((s, e, u, ch, props, vh, cu))
            if os.environ.get("POLL_S") and cu.endswith("7831"):
                poll_state(h, att, vh)
                return att, found
            want = os.environ.get("NOTIFY_UUID")
            if want and cu.endswith(want) and (props & 0x10):
                # notify-only characteristics are never read: subscribe right away
                subscribe_and_listen(h, att, cu, vh)
                return att, found
            if not read_all or not (props & 0x02):
                continue
            # DataSource / NotificationSource are notify-only in practice: the device
            # never answers a Read Request for them, and the ATT channel then goes quiet.
            if (cu.endswith("7835") or cu.endswith("7837")) and \
                    os.environ.get("ATT_READ_NOTIFY") != "1":
                print("      (notify-only, read skipped)")
                continue
            val = None
            for attempt in range(int(os.environ.get("ATT_READ_TRIES", "2"))):
                try:
                    val = att.read(vh)
                    break
                except Exception as exc:
                    if attempt == 0:
                        print(f"      read retry ({exc})")
                        for _ in range(3):
                            h.pump(100)
            if val is None:
                print("      read failed")
                continue
            txt = val.hex()
            if cu.endswith("7831"):
                print(f"      state {decode_state(val)}")
            want = os.environ.get("NOTIFY_UUID")
            if want and cu.endswith(want) and (props & 0x10):
                subscribe_and_listen(h, att, cu, vh)
                return att, found
            try:
                dec = val.decode("utf-8")
                if dec.isprintable():
                    txt = repr(dec)
            except Exception:
                pass
            print(f"      value = {txt}")

    return att, found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stage", choices=["list", "probe", "init", "le-scan", "ext-scan", "gatt", "smp", "pair-gatt", "inquiry", "all"])
    ap.add_argument("--fake", action="store_true", help="use the software controller model")
    ap.add_argument("--vid"), ap.add_argument("--pid")
    ap.add_argument("--fw-dir", default=os.path.join(HERE, "firmware"))
    ap.add_argument("--skip-fw", action="store_true", help="do not download Realtek firmware")
    ap.add_argument("--no-detach", action="store_true", help="never detach a kernel driver")
    ap.add_argument("--seconds", type=float, default=5.0)
    ap.add_argument("--addr", default=None,
                    help="peer BD_ADDR (aa:bb:cc:dd:ee:ff); required for gatt/smp/pair-gatt")
    ap.add_argument("--btsnoop", metavar="PATH", help="write a btsnoop (H4) capture of all HCI traffic")
    ap.add_argument("--btsnoop-max-mb", type=float, default=None,
                    help="rotate the capture at this size (PATH.1, PATH.2, ... keep 3)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    if args.stage in ("gatt", "smp", "pair-gatt") and not args.addr:
        ap.error(f"--addr is required for stage '{args.stage}'")
    logpath = setup_logging(args.verbose)
    print(f"log: {logpath}")

    if args.stage == "list" and not args.fake:
        return cmd_list()

    from rtlhci.usb_transport import UsbClaimError
    snoop = open_snoop(args)
    if snoop:
        print(f"btsnoop: {args.btsnoop}")
    try:
        t = open_transport(args, snoop)
    except UsbClaimError as e:
        print(str(e))
        logging.error("%s", e)
        if snoop:
            snoop.close()
        return 3
    except Exception as e:
        print(f"NG open: {e}")
        logging.exception("open")
        if snoop:
            snoop.close()
        return 3
    for step, ok, detail in getattr(t, "diag", []):
        print(f"  [{'OK' if ok else 'NG'}] {step}: {detail}")
    rc = 0
    try:
        if args.stage == "probe":
            print("probe OK: interface claimed; releasing")
            return 0
        h = Hci(t)
        rtl = RtlSetup(h, None if args.skip_fw else args.fw_dir)
        info = rtl.run(skip_firmware=args.skip_fw)
        for line in info.log:
            print("  rtl:", line)
        if info.fw_file:
            print("  fw :", info.fw_file)
        if info.cfg_file:
            print("  cfg:", info.cfg_file)
        std = h.init_standard()
        v = std["version"]
        print(f"HCI ver=0x{v.hci_ver:02x} rev=0x{v.hci_rev:04x} lmp=0x{v.lmp_ver:02x} "
              f"subver=0x{v.lmp_subver:04x} manuf={v.manufacturer}")
        print(f"BD_ADDR {std['bd_addr']}  ACL {std['buffer']}  LE {std.get('le_buffer')}")
        try:
            print(f"name: {h.read_local_name()!r}")
        except Exception as e:
            print(f"read_local_name: {e}")
        if args.stage == "smp":
            from rtlhci.acl import L2cap
            from rtlhci.smp import Smp
            l2 = L2cap(h)
            handle = h.le_create_connection(args.addr, timeout=15.0)
            print(f"LE connected handle=0x{handle:04x}")
            print("conn:", h.le_conns.get(handle))
            from rtlhci.smp import SmpConfig
            smp = Smp(h, l2, SmpConfig(mitm=False))
            if not os.environ.get("SMP_WAIT_PEER"):
                smp.pair(handle)
            else:
                print("waiting for peer-initiated pairing")
            for i in range(800):
                h.pump(100)
                if i % 50 == 0:
                    print(f"  smp t={i/10:.0f}s state={[str(x.state) for x in smp.sessions.values()]}")
                if handle in smp.encrypted:
                    print("SMP: encrypted=1")
                    raise SystemExit(0)
                if smp.errors:
                    print(f"SMP errors={smp.errors}")
                    raise SystemExit(1)
            print("SMP: no encryption result")
            raise SystemExit(1)
        if args.stage == "gatt":
            from rtlhci.acl import L2cap
            l2 = L2cap(h)
            handle = h.le_create_connection(args.addr, timeout=15.0)
            print(f"LE connected handle=0x{handle:04x}")
            # MTU skipped after the device ignored Exchange MTU; explore directly.
            explore_gatt(h, l2, handle)
            raise SystemExit(0)
        if args.stage == "pair-gatt":
            from rtlhci.acl import L2cap
            from rtlhci.smp import Smp, SmpConfig
            l2 = L2cap(h)
            # The device only accepts pairing for a couple of seconds after the button
            # press, so keep reconnecting until one attempt gets through.
            budget = float(os.environ.get("PAIR_RETRY_S", "40"))
            deadline = time.monotonic() + budget
            handle = None
            attempt = 0
            while time.monotonic() < deadline:
                attempt += 1
                try:
                    handle = h.le_create_connection(args.addr, timeout=15.0)
                except Exception as exc:
                    print(f"  attempt {attempt}: connect failed: {exc}")
                    time.sleep(0.5)
                    continue
                cfg = SmpConfig(mitm=False)
                if os.environ.get("SMP_NO_BOND") == "1":
                    cfg.bonding = False
                if os.environ.get("SMP_KEYDIST") is not None:
                    kd = int(os.environ["SMP_KEYDIST"], 0)
                    cfg.init_key_dist = cfg.resp_key_dist = kd
                smp = Smp(h, l2, cfg)
                smp.pair(handle)
                ok = False
                for _ in range(120):           # <= 12 s per attempt
                    h.pump(100)
                    if handle in smp.encrypted:
                        ok = True
                        break
                    if smp.errors or handle not in h.le_conns:
                        break
                if ok:
                    print(f"LE connected handle=0x{handle:04x} (attempt {attempt})")
                    print("SMP: encrypted=1")
                    settle = float(os.environ.get("PAIR_SETTLE_S", "1.5"))
                    for _ in range(int(settle * 10)):
                        h.pump(100)
                    break
                print(f"  attempt {attempt}: no pairing (window closed?)")
            else:
                print("SMP: no encryption result (retry budget exhausted)")
                raise SystemExit(1)
            # Some peripherals stay silent on ATT for a while after pairing;
            # keep asking (read-only) until the deadline.
            # until ATT_WAIT_S expires.
            limit = time.monotonic() + float(os.environ.get("ATT_WAIT_S", "30"))
            while True:
                try:
                    explore_gatt(h, l2, handle)
                    break
                except Exception as exc:
                    if time.monotonic() >= limit:
                        raise
                    print(f"  ATT retry after {type(exc).__name__}: {exc}")
                    for _ in range(5):
                        h.pump(100)
            raise SystemExit(0)
        if args.stage == "ext-scan":
            seen = h.le_scan_ext(args.seconds)
            print(f"LE extended scan: {len(seen)} devices")
            for a, d in sorted(seen.items(), key=lambda kv: -(kv[1].get("rssi") or -999))[:20]:
                print(f"  {a} phy={d.get('primary_phy')} rssi={d.get('rssi')} "
                      f"name={d.get('name','')!r} mfg={d.get('mfg')}")
            snoop = None
        if args.stage in ("le-scan", "all"):
            seen = h.le_scan(args.seconds)
            print(f"LE scan: {len(seen)} devices")
            for a, r in sorted(seen.items(), key=lambda kv: -kv[1].get("rssi", -999)):
                print(f"  {a} t{r.get('addr_type')} rssi={r.get('rssi')} name={r.get('name', '')!r} "
                      f"uuid16={r.get('uuid16', [])} mfg={r.get('mfg', [])}")
        if args.stage in ("inquiry", "all"):
            h.write_inquiry_mode(2)
            found = h.inquiry(args.seconds)
            print(f"Inquiry: {len(found)} devices")
            for a, r in found.items():
                print(f"  {a} cod=0x{r.get('cod', 0):06x} rssi={r.get('rssi')} name={r.get('name', '')!r}")
        print("SELFTEST OK")
    except Exception as e:
        rc = 4
        print(f"SELFTEST NG: {e}")
        logging.error("%s", traceback.format_exc())
    finally:
        t.close()
        if snoop:
            snoop.close()
            print(f"btsnoop: {snoop.total_records} records, {snoop.drops} dropped, "
                  f"{snoop.rotations} rotations -> {args.btsnoop}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
