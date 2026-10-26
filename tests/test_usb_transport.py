import pytest
from rtlhci.fake import FakeController, FakeUsbDevice, FakeUsbUtil, FakeUSBError
from rtlhci.hci import Hci
from rtlhci.acl import L2cap, build_sig, SIG, CID_SIGNALING, L2capReassembler, parse_sig
from rtlhci.usb_transport import UsbTransport, UsbClaimError, describe_usb_error, find_bt_devices


def open_ok(**kw):
    ctl = FakeController()
    dev = FakeUsbDevice(ctl, **kw)
    util = FakeUsbUtil()
    return ctl, dev, util, UsbTransport(dev, usb_util=util, plat="Darwin")


def test_open_claim_and_endpoints():
    ctl, dev, util, t = open_ok()
    assert util.claimed == [0]
    assert (t.ep.intr_in, t.ep.bulk_in, t.ep.bulk_out, t.ep.intr_mps) == (0x81, 0x82, 0x02, 16)
    t.close()
    assert util.released == [0]


def test_full_init_over_usb_with_16_byte_interrupt_chunks():
    ctl, dev, util, t = open_ok()
    h = Hci(t, cmd_timeout_s=0.5)
    info = h.init_standard()
    assert info["bd_addr"] == "E8:48:B8:C8:20:00"
    assert h.read_local_name() == "RTL8761BU fake"  # 252-byte event = 16 interrupt packets
    assert all(c == (0x20, 0, 0, 0) for c in dev.ctrl_log)


def test_acl_over_bulk_split_at_64():
    ctl, dev, util, t = open_ok()
    h = Hci(t, cmd_timeout_s=0.5)
    h.init_standard()
    ctl.connect_bredr(0x40)
    h.pump(5)
    l2 = L2cap(h)
    ctl.send_l2cap(0x40, CID_SIGNALING, build_sig(SIG.ECHO_REQ, 1, b"x" * 200), frag=300)
    h.pump(5)
    out = []
    r = L2capReassembler(lambda a, b, p: out.append(parse_sig(p)[0]))
    for p in ctl.acl_in:
        r.feed(p)
    assert out == [(SIG.ECHO_RSP, 1, b"x" * 200)]


def test_detach_when_kernel_driver_active():
    ctl, dev, util, t = open_ok(kernel_driver=True)
    assert dev.detached == [0] and t.detached == [0]


def test_macos_detach_access_denied_reports_diagnostics():
    ctl = FakeController()
    dev = FakeUsbDevice(ctl, kernel_driver=True,
                        detach_error=FakeUSBError("Access denied (insufficient permissions)", -3, 13))
    with pytest.raises(UsbClaimError) as e:
        UsbTransport(dev, usb_util=FakeUsbUtil(), plat="Darwin")
    msg = str(e.value)
    assert "detach_kernel_driver(0)" in msg and "LIBUSB_ERROR_ACCESS" in msg
    assert "com.apple.vm.device-access" in msg and "USB passthrough" in msg


def test_macos_claim_busy():
    ctl = FakeController()
    dev = FakeUsbDevice(ctl)
    util = FakeUsbUtil(claim_error=FakeUSBError("Resource busy", -6, 16))
    with pytest.raises(UsbClaimError) as e:
        UsbTransport(dev, usb_util=util, plat="Darwin")
    assert "claim_interface(0)" in str(e.value) and "LIBUSB_ERROR_BUSY" in str(e.value)
    assert "bluetoothd" in str(e.value)


def test_kernel_driver_query_not_supported_is_tolerated():
    ctl, dev, util, t = open_ok(kda_error=FakeUSBError("Operation not supported", -12))
    assert util.claimed == [0]
    assert any(step.startswith("is_kernel_driver_active") and ok for step, ok, _ in t.diag)


def test_unconfigured_device_gets_set_configuration():
    ctl, dev, util, t = open_ok(configured=False)
    assert dev.configured and util.claimed == [0]


def test_linux_hints():
    ctl = FakeController()
    with pytest.raises(UsbClaimError) as e:
        UsbTransport(FakeUsbDevice(ctl), usb_util=FakeUsbUtil(FakeUSBError("busy", -6, 16)), plat="Linux")
    assert "btusb" in str(e.value)


def test_describe_error():
    s = describe_usb_error(FakeUSBError("x", -4, 19))
    assert "LIBUSB_ERROR_NO_DEVICE" in s and "ENODEV" in s


def test_find_bt_devices_filters():
    class Other:
        idVendor, idProduct, bDeviceClass, bDeviceSubClass, bDeviceProtocol = 0x05AC, 0x1234, 0, 0, 0
        def __iter__(self):
            return iter([])

    class Core:
        @staticmethod
        def find(find_all=True):
            return [Other(), FakeUsbDevice(FakeController())]
    devs = find_bt_devices(Core)
    assert len(devs) == 1 and devs[0].idProduct == 0x0604
