"""rtlhci: userspace Bluetooth HCI stack over libusb, with Realtek RTL8761 support.

Layers (bottom-up):
  usb_transport  -- libusb (pyusb) access to a BT USB class 0xE0 device
  hci            -- HCI packet build/parse, command flow, event dispatch
  acl            -- ACL fragmentation/reassembly + L2CAP basic framing
  rtl            -- Realtek vendor commands, epatch parsing, firmware download
  smp            -- LE Security Manager (pairing, key distribution, encryption start)
  smp_crypto     -- SMP crypto toolbox + P-256
  btsnoop        -- btsnoop/H4 capture, hooked at the transport boundary
"""
__version__ = "0.2.0"
