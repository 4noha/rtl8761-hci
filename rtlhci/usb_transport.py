"""libusb (pyusb) transport for Bluetooth USB class devices (0xE0/0x01/0x01).

Endpoint map per Bluetooth Core spec, Vol 4 Part B (USB transport):
  control EP0  : HCI commands   (bmRequestType 0x20, bRequest 0, wIndex = iface)
  interrupt IN : HCI events     (UB500: 0x81, wMaxPacketSize 16)
  bulk OUT     : ACL data out   (UB500: 0x02)
  bulk IN      : ACL data in    (UB500: 0x82)
  iface 1      : isochronous SCO (not used here)

Every step of open/detach/claim is recorded in `self.diag` so a failure on
macOS (Apple's Bluetooth stack holding the device) is reported precisely.
"""
from __future__ import annotations

import errno as _errno
import logging
import platform
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .btsnoop import H4_ACL, H4_CMD, H4_EVT
from .transport import StreamReassembler, Transport, TransportError

log = logging.getLogger("rtlhci.usb")

BT_CLASS, BT_SUBCLASS, BT_PROTOCOL = 0xE0, 0x01, 0x01

# Known RTL8761B/BU dongles (VID, PID, name). UB500 and UB500 Plus both report
# 2357:0604 according to public reports; verify with `selftest.py list`.
KNOWN_IDS = {
    (0x2357, 0x0604): "TP-Link UB500 / UB500 Plus (RTL8761BUV)",
    (0x0BDA, 0x8771): "Realtek RTL8761BU reference",
    (0x0BDA, 0xA725): "Realtek RTL8761BU (alt)",
    (0x0B05, 0x190E): "ASUS USB-BT500 (RTL8761BU)",
    (0x2550, 0x8761): "Generic RTL8761BU",
    (0x2C0A, 0x8761): "Generic RTL8761BU",
}

# libusb error codes -> name, explanation useful on macOS
LIBUSB_ERRORS = {
    -1: ("LIBUSB_ERROR_IO", "I/O error"),
    -2: ("LIBUSB_ERROR_INVALID_PARAM", "invalid parameter"),
    -3: ("LIBUSB_ERROR_ACCESS", "access denied (need root / entitlement, or another driver owns it)"),
    -4: ("LIBUSB_ERROR_NO_DEVICE", "device unplugged / re-enumerated"),
    -5: ("LIBUSB_ERROR_NOT_FOUND", "entity not found (no kernel driver attached, or bad iface)"),
    -6: ("LIBUSB_ERROR_BUSY", "resource busy: another driver/process has claimed the interface"),
    -7: ("LIBUSB_ERROR_TIMEOUT", "timeout"),
    -8: ("LIBUSB_ERROR_OVERFLOW", "overflow"),
    -9: ("LIBUSB_ERROR_PIPE", "pipe error / endpoint stalled"),
    -10: ("LIBUSB_ERROR_INTERRUPTED", "interrupted"),
    -11: ("LIBUSB_ERROR_NO_MEM", "no memory"),
    -12: ("LIBUSB_ERROR_NOT_SUPPORTED", "operation not supported on this platform/backend"),
    -99: ("LIBUSB_ERROR_OTHER", "other error"),
}


class UsbClaimError(TransportError):
    def __init__(self, msg: str, diag: list, hints: list[str]):
        self.diag, self.hints = diag, hints
        lines = [msg, "--- diagnostics ---"]
        lines += [f"  [{'OK' if ok else 'NG'}] {step}: {detail}" for step, ok, detail in diag]
        if hints:
            lines.append("--- hints ---")
            lines += [f"  * {h}" for h in hints]
        super().__init__("\n".join(lines))


def describe_usb_error(exc: BaseException) -> str:
    code = getattr(exc, "backend_error_code", None)
    eno = getattr(exc, "errno", None)
    name, why = LIBUSB_ERRORS.get(code, (None, None)) if code is not None else (None, None)
    parts = [f"{type(exc).__name__}: {exc}"]
    if code is not None:
        parts.append(f"libusb={code}{'/' + name if name else ''}")
    if eno is not None:
        parts.append(f"errno={eno}/{_errno.errorcode.get(eno, '?')}")
    if why:
        parts.append(why)
    return " | ".join(parts)


def _hints_for(exc: BaseException, plat: str) -> list[str]:
    code = getattr(exc, "backend_error_code", None)
    eno = getattr(exc, "errno", None)
    h = []
    if plat == "Darwin":
        if code in (-3, -6) or eno in (_errno.EACCES, _errno.EBUSY, _errno.EPERM):
            h += [
                "macOS: Apple's Bluetooth stack (bluetoothd / IOBluetooth USB transport) "
                "or another kext may own this interface.",
                "macOS: libusb detach needs root (sudo) or the com.apple.vm.device-access "
                "entitlement; try once with sudo to distinguish 'permission' from 'owned'.",
                "Check owner: `ioreg -p IOUSB -l -w0 | grep -A30 -i 'UB500\\|8761'` "
                "(look for IOBluetooth* clients under the interface).",
                "Fallback A: plug the dongle into a Linux box, `sudo systemctl stop bluetooth` "
                "and unbind btusb (see README).",
                "Fallback B: Linux VM on the Mac (UTM/Parallels/VMware) with USB passthrough "
                "of 2357:0604 -- the hypervisor captures the device away from macOS.",
            ]
        if code == -12:
            h.append("macOS: this libusb build lacks kernel-driver detach support "
                     "(needs libusb >= 1.0.25); `brew upgrade libusb`.")
    elif plat == "Linux":
        if code in (-3,) or eno == _errno.EACCES:
            h.append("Linux: add a udev rule for the VID:PID or run with sudo.")
        if code in (-6,) or eno == _errno.EBUSY:
            h.append("Linux: btusb holds it -- `sudo systemctl stop bluetooth` and "
                     "echo the interface into /sys/bus/usb/drivers/btusb/unbind.")
    if code == -4:
        h.append("Device re-enumerated (common right after firmware download or detach); retry open.")
    return h


@dataclass
class UsbEndpoints:
    intr_in: int = 0x81
    bulk_in: int = 0x82
    bulk_out: int = 0x02
    intr_mps: int = 16
    bulk_mps: int = 64


def find_bt_devices(usb_core: Any = None) -> list:
    """Return pyusb devices that look like BT controllers (class or known ID)."""
    if usb_core is None:
        import usb.core as usb_core  # type: ignore
    found = []
    for dev in usb_core.find(find_all=True):
        vidpid = (dev.idVendor, dev.idProduct)
        is_bt = (dev.bDeviceClass, dev.bDeviceSubClass, dev.bDeviceProtocol) == (
            BT_CLASS, BT_SUBCLASS, BT_PROTOCOL)
        if not is_bt:
            try:
                for cfg in dev:
                    for intf in cfg:
                        if (intf.bInterfaceClass, intf.bInterfaceSubClass,
                                intf.bInterfaceProtocol) == (BT_CLASS, BT_SUBCLASS, BT_PROTOCOL):
                            is_bt = True
            except Exception:  # descriptor read may fail without permission
                pass
        if is_bt or vidpid in KNOWN_IDS:
            found.append(dev)
    return found


class UsbTransport(Transport):
    """Owns interface 0 of a BT USB device via libusb."""

    def __init__(self, dev: Any, *, iface: int = 0, usb_util: Any = None,
                 detach: bool = True, plat: Optional[str] = None,
                 ctrl_timeout_ms: int = 1000, snoop: Any = None):
        self.dev = dev
        self.snoop = snoop  # BtSnoopWriter or None
        self.iface = iface
        self.ep = UsbEndpoints()
        self.diag: list = []
        self.detached: list[int] = []
        self.claimed = False
        self.plat = plat or platform.system()
        self.ctrl_timeout_ms = ctrl_timeout_ms
        if usb_util is None:
            import usb.util as usb_util  # type: ignore
        self.util = usb_util
        self._evt = StreamReassembler(2, 1, 1)
        self._acl = StreamReassembler(4, 2, 2)
        self._evq: list[bytes] = []
        self._aclq: list[bytes] = []
        self._open(detach)

    # ------------------------------------------------------------ open/claim
    def _step(self, name: str, fn: Callable[[], Any], *, fatal: bool = True,
              ok_codes: tuple = ()) -> Any:
        try:
            r = fn()
            self.diag.append((name, True, repr(r) if r is not None else "ok"))
            log.debug("usb step %s ok (%r)", name, r)
            return r
        except Exception as exc:  # noqa: BLE001 -- want everything logged
            desc = describe_usb_error(exc)
            code = getattr(exc, "backend_error_code", None)
            tolerated = code in ok_codes
            self.diag.append((name, tolerated, desc))
            (log.info if tolerated else log.error)("usb step %s: %s", name, desc)
            if fatal and not tolerated:
                raise UsbClaimError(f"USB open failed at step '{name}'", self.diag,
                                    _hints_for(exc, self.plat)) from exc
            return None

    def _open(self, detach: bool) -> None:
        d = self.dev
        self.diag.append(("platform", True, f"{self.plat} {platform.release()} py{sys.version.split()[0]}"))
        self.diag.append(("device", True, f"{d.idVendor:04x}:{d.idProduct:04x} "
                          f"{KNOWN_IDS.get((d.idVendor, d.idProduct), 'unknown model')}"))
        for i in (0, 1):
            active = self._step(f"is_kernel_driver_active({i})",
                                lambda i=i: d.is_kernel_driver_active(i),
                                fatal=False, ok_codes=(-12, -5))
            if active and detach:
                self._step(f"detach_kernel_driver({i})", lambda i=i: d.detach_kernel_driver(i))
                self.detached.append(i)
            elif active:
                raise UsbClaimError("kernel driver active and detach disabled", self.diag,
                                    ["re-run with detach enabled"])
        # set_configuration may fail with BUSY when already configured by OS; tolerate.
        cfg = self._step("get_active_configuration", d.get_active_configuration, fatal=False)
        if cfg is None:
            self._step("set_configuration", d.set_configuration, ok_codes=(-6,))
            cfg = self._step("get_active_configuration(2)", d.get_active_configuration)
        self._discover_endpoints(cfg)
        self._step(f"claim_interface({self.iface})", lambda: self.util.claim_interface(d, self.iface))
        self.claimed = True

    def _discover_endpoints(self, cfg: Any) -> None:
        try:
            intf = cfg[(self.iface, 0)]
            for e in intf:
                addr, attr, mps = e.bEndpointAddress, e.bmAttributes & 3, e.wMaxPacketSize
                is_in = bool(addr & 0x80)
                if attr == 3 and is_in:
                    self.ep.intr_in, self.ep.intr_mps = addr, mps
                elif attr == 2 and is_in:
                    self.ep.bulk_in, self.ep.bulk_mps = addr, mps
                elif attr == 2:
                    self.ep.bulk_out = addr
            self.diag.append(("endpoints", True, repr(self.ep)))
        except Exception as exc:  # fall back to UB500 defaults
            self.diag.append(("endpoints", False, f"{describe_usb_error(exc)}; using defaults {self.ep}"))

    # ------------------------------------------------------------ I/O
    @staticmethod
    def _is_timeout(exc: BaseException) -> bool:
        return (type(exc).__name__ == "USBTimeoutError"
                or getattr(exc, "backend_error_code", None) == -7
                or getattr(exc, "errno", None) in (_errno.ETIMEDOUT, 60))  # 60 = macOS ETIMEDOUT

    def send_command(self, pkt: bytes) -> None:
        try:
            n = self.dev.ctrl_transfer(0x20, 0x00, 0x0000, self.iface, pkt, self.ctrl_timeout_ms)
        except Exception as exc:
            raise TransportError(f"HCI command ctrl_transfer failed: {describe_usb_error(exc)}") from exc
        if n != len(pkt):
            raise TransportError(f"short ctrl write {n}/{len(pkt)}")
        self._snoop(H4_CMD, pkt, False)

    def _read(self, ep: int, size: int, timeout_ms: int) -> Optional[bytes]:
        try:
            return bytes(self.dev.read(ep, size, timeout_ms))
        except Exception as exc:
            if self._is_timeout(exc):
                return None
            raise TransportError(f"read ep 0x{ep:02x} failed: {describe_usb_error(exc)}") from exc

    def read_event(self, timeout_ms: int) -> Optional[bytes]:
        if self._evq:
            return self._evq.pop(0)
        # loop: a single event may span several 16-byte interrupt packets
        while True:
            chunk = self._read(self.ep.intr_in, 1024, timeout_ms)
            if chunk is None:
                return None
            for p in self._evt.feed(chunk):
                self._snoop(H4_EVT, p, True)
                self._evq.append(p)
            if self._evq:
                return self._evq.pop(0)

    def send_acl(self, pkt: bytes) -> None:
        try:
            n = self.dev.write(self.ep.bulk_out, pkt, self.ctrl_timeout_ms)
        except Exception as exc:
            raise TransportError(f"ACL bulk write failed: {describe_usb_error(exc)}") from exc
        if n != len(pkt):
            raise TransportError(f"short bulk write {n}/{len(pkt)}")
        self._snoop(H4_ACL, pkt, False)

    def read_acl(self, timeout_ms: int) -> Optional[bytes]:
        if self._aclq:
            return self._aclq.pop(0)
        while True:
            chunk = self._read(self.ep.bulk_in, 4096, timeout_ms)
            if chunk is None:
                return None
            for p in self._acl.feed(chunk):
                self._snoop(H4_ACL, p, True)
                self._aclq.append(p)
            if self._aclq:
                return self._aclq.pop(0)

    def close(self) -> None:
        if self.claimed:
            self._step(f"release_interface({self.iface})",
                       lambda: self.util.release_interface(self.dev, self.iface), fatal=False)
            self.claimed = False
        for i in self.detached:
            self._step(f"attach_kernel_driver({i})", lambda i=i: self.dev.attach_kernel_driver(i),
                       fatal=False)
        self.detached = []
        try:
            self.util.dispose_resources(self.dev)
        except Exception:
            pass


def open_first(vid: Optional[int] = None, pid: Optional[int] = None, **kw) -> UsbTransport:
    devs = find_bt_devices()
    if vid is not None:
        devs = [d for d in devs if d.idVendor == vid and (pid is None or d.idProduct == pid)]
    if not devs:
        raise TransportError("no Bluetooth USB device found (class e0/01/01 or known RTL8761 ID). "
                             "On macOS also check System Information > USB.")
    return UsbTransport(devs[0], **kw)
