"""Realtek RTL8761 vendor support (independent implementation).

The bring-up sequence below was implemented from the vendor command behaviour observed on
hardware and from the publicly documented epatch container layout. No vendor source file is
included or translated.

Bring-up sequence:
  1. vendor 0xFC61 read_reg16 RTL_CHIP_SUBVER (just like Linux; result ignored
     unless 8822B)
  2. HCI Read_Local_Version -> (lmp_subver, hci_rev, hci_ver) -> IC table match
     * no match (firmware already loaded -> subver changed) -> send 0xFC66
       "drop fw" once, wait 200 ms, retry; still no match -> assume patched.
  3. vendor 0xFC6D read ROM version (has_rom_version chips) -> rom_version
  4. vendor 0xFC61 RTL_SEC_PROJ -> key_id (0 = no secure-boot sections)
  5. load rtl8761bu_fw.bin (+ rtl8761bu_config.bin when key_id == 0)
  6. parse epatch (v1 "Realtech" / v2 "RTBTCore"), pick patch for
     chip_id == rom_version + 1, append config blob
  7. 0xFC20 download in 252-byte fragments, index 0..0x7f wrapping to 1,
     last fragment index |= 0x80
  8. Read_Local_Version to confirm; caller then HCI_Reset.
"""
from __future__ import annotations

import hashlib
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from .hci import Hci, HciError, OP

log = logging.getLogger("rtlhci.rtl")

RTL_EPATCH_SIGNATURE = b"Realtech"
RTL_EPATCH_SIGNATURE_V2 = b"RTBTCore"
EXTENSION_SIG = bytes([0x51, 0x04, 0xFD, 0x77])
RTL_FRAG_LEN = 252

RTL_ROM_LMP_8723A = 0x1200
RTL_ROM_LMP_8723B = 0x8723
RTL_ROM_LMP_8821A = 0x8821
RTL_ROM_LMP_8761A = 0x8761
RTL_ROM_LMP_8703B = 0x8703
RTL_ROM_LMP_8822B = 0x8822
RTL_ROM_LMP_8852A = 0x8852
RTL_ROM_LMP_8851B = 0x8851
RTL_ROM_LMP_8922A = 0x8922

RTL_CHIP_SUBVER = bytes([0x10, 0x38, 0x04, 0x28, 0x80])
RTL_CHIP_REV = bytes([0x10, 0x3A, 0x04, 0x28, 0x80])
RTL_SEC_PROJ = bytes([0x10, 0xA4, 0xAD, 0x00, 0xB0])

RTL_PATCH_SNIPPETS = 0x01
RTL_PATCH_DUMMY_HEADER = 0x02
RTL_PATCH_SECURITY_HEADER = 0x03

PROJECT_ID_TO_LMP = {
    0: RTL_ROM_LMP_8723A, 1: RTL_ROM_LMP_8723B, 2: RTL_ROM_LMP_8821A, 3: RTL_ROM_LMP_8761A,
    7: RTL_ROM_LMP_8703B, 8: RTL_ROM_LMP_8822B, 9: RTL_ROM_LMP_8723B, 10: RTL_ROM_LMP_8821A,
    13: RTL_ROM_LMP_8822B, 14: RTL_ROM_LMP_8761A, 18: RTL_ROM_LMP_8852A, 20: RTL_ROM_LMP_8852A,
    25: RTL_ROM_LMP_8852A, 36: RTL_ROM_LMP_8851B, 44: RTL_ROM_LMP_8922A, 47: RTL_ROM_LMP_8852A,
    51: RTL_ROM_LMP_8761A,
}

HCI_USB, HCI_UART = 1, 3  # matches Linux HCI_USB / HCI_UART bus constants


@dataclass(frozen=True)
class IcInfo:
    lmp_subver: int
    hci_rev: int
    hci_ver: int
    bus: int
    fw_name: str
    cfg_name: Optional[str]
    hw_info: str
    has_rom_version: bool = True
    config_needed: bool = False


# 8761 family chip table (match on lmp_subver, hci_rev, hci_ver, bus)
IC_TABLE = [
    IcInfo(RTL_ROM_LMP_8761A, 0x0A, 0x06, HCI_USB, "rtl8761a_fw", "rtl8761a_config", "rtl8761au"),
    IcInfo(RTL_ROM_LMP_8761A, 0x0B, 0x0A, HCI_UART, "rtl8761b_fw", "rtl8761b_config", "rtl8761btv"),
    IcInfo(RTL_ROM_LMP_8761A, 0x0B, 0x0A, HCI_USB, "rtl8761bu_fw", "rtl8761bu_config", "rtl8761bu"),
    IcInfo(RTL_ROM_LMP_8761A, 0x0E, 0x00, HCI_USB, "rtl8761cu_fw", "rtl8761cu_config", "rtl8761cu"),
]


def match_ic(lmp_subver: int, hci_rev: int, hci_ver: int, bus: int = HCI_USB) -> Optional[IcInfo]:
    for ic in IC_TABLE:
        if ic.lmp_subver != lmp_subver or ic.hci_rev != hci_rev or ic.bus != bus:
            continue
        if ic.hci_ver not in (0, hci_ver):
            continue
        return ic
    return None


class FirmwareError(Exception):
    pass


@dataclass
class ParsedPatch:
    format: str           # "v1" or "v2"
    project_id: int
    fw_version: int       # v1: le32; v2: first 4 bytes of 8-byte version
    payload: bytes        # bytes to download (before config is appended)
    notes: list = field(default_factory=list)


def find_project_id(fw: bytes, hdr_size: int) -> int:
    """Walk the extension section backwards from the trailing signature."""
    if fw[-4:] != EXTENSION_SIG:
        raise FirmwareError("extension section signature mismatch")
    p = len(fw) - 4
    while p >= hdr_size + 3:
        opc, ln, data = fw[p - 1], fw[p - 2], fw[p - 3]
        p -= 3
        if opc == 0xFF:
            break
        if ln == 0:
            raise FirmwareError("found instruction with length 0")
        if opc == 0 and ln == 1:
            return data
        p -= ln
    raise FirmwareError("failed to find version (project id) instruction")


def parse_epatch(fw: bytes, rom_version: int, lmp_subver: int = RTL_ROM_LMP_8761A,
                 key_id: int = 0) -> ParsedPatch:
    if len(fw) <= 8:
        raise FirmwareError("firmware too short")
    sig = fw[:8]
    if sig == RTL_EPATCH_SIGNATURE:
        hdr_size = 14
    elif sig == RTL_EPATCH_SIGNATURE_V2:
        hdr_size = 20
    else:
        raise FirmwareError(f"bad EPATCH signature {sig!r}")
    if len(fw) < hdr_size + 4 + 3:
        raise FirmwareError("firmware shorter than header + extension")
    pid = find_project_id(fw, hdr_size)
    if pid not in PROJECT_ID_TO_LMP:
        raise FirmwareError(f"unknown project id {pid}")
    if PROJECT_ID_TO_LMP[pid] != lmp_subver:
        raise FirmwareError(f"firmware is for {PROJECT_ID_TO_LMP[pid]:x} but this is a {lmp_subver:x}")
    if sig == RTL_EPATCH_SIGNATURE_V2:
        return _parse_v2(fw, rom_version, key_id, pid)

    fw_version, num = struct.unpack_from("<IH", fw, 8)
    if len(fw) < hdr_size + 7 + 8 * num:
        raise FirmwareError("firmware too short for patch table")
    chip_base, len_base, off_base = 14, 14 + 2 * num, 14 + 4 * num
    patch_len = patch_off = 0
    chips = []
    for i in range(num):
        chip = struct.unpack_from("<H", fw, chip_base + 2 * i)[0]
        chips.append(chip)
        if chip == rom_version + 1:
            patch_len = struct.unpack_from("<H", fw, len_base + 2 * i)[0]
            patch_off = struct.unpack_from("<I", fw, off_base + 4 * i)[0]
            break
    if not patch_off:
        raise FirmwareError(f"didn't find patch for chip id {rom_version} (file has chip ids {chips})")
    if patch_len < 4 or patch_off > len(fw) or patch_len > len(fw) - patch_off:
        raise FirmwareError("patch offset/length out of range")
    payload = fw[patch_off:patch_off + patch_len - 4] + struct.pack("<I", fw_version)
    return ParsedPatch("v1", pid, fw_version, payload, [f"num_patches={num} chips={chips}",
                                                         f"off=0x{patch_off:x} len=0x{patch_len:x}"])


def _parse_v2(fw: bytes, rom_version: int, key_id: int, pid: int) -> ParsedPatch:
    end = len(fw) - 7  # cut the tail, as Linux does
    fwver = fw[8:16]
    nsec = struct.unpack_from("<I", fw, 16)[0]
    i = 20
    subsecs = []  # (prio, order, data)
    order = 0
    for _ in range(nsec):
        if i + 8 > end:
            break
        opc, slen = struct.unpack_from("<II", fw, i)
        i += 8
        if i + slen > end:
            break
        sec = fw[i:i + slen]
        i += slen
        if opc == RTL_PATCH_SECURITY_HEADER and not key_id:
            continue
        if opc not in (RTL_PATCH_SNIPPETS, RTL_PATCH_SECURITY_HEADER, RTL_PATCH_DUMMY_HEADER):
            continue
        num = struct.unpack_from("<H", sec, 0)[0]
        j = 4
        for _ in range(num):
            if j + 8 > len(sec):
                break
            eco, prio, b2, _b3, ln = struct.unpack_from("<BBBBI", sec, j)
            data = sec[j + 8:j + 8 + ln]
            if len(data) < ln:
                break
            j += 8 + ln
            if eco != rom_version + 1:
                continue
            if opc == RTL_PATCH_SECURITY_HEADER and b2 != key_id:
                continue
            subsecs.append((prio, order, data))
            order += 1
    if not subsecs:
        raise FirmwareError("v2: no subsections for this chip (ENODATA)")
    # Keep the patch list ordered by priority: insert before the first entry with prio >= new
    # -> ascending prio; on ties the later-parsed subsection ends up first.
    subsecs.sort(key=lambda t: (t[0], -t[1]))
    payload = b"".join(d for _, _, d in subsecs)
    return ParsedPatch("v2", pid, struct.unpack_from("<I", fwver)[0], payload,
                       [f"sections={nsec} subsecs={len(subsecs)} key_id={key_id}"])


def fragments(data: bytes) -> list[bytes]:
    """0xFC20 parameter blocks, bug-compatible with Linux rtl_download_firmware."""
    frag_num = len(data) // RTL_FRAG_LEN + 1
    out, j = [], 0
    for i in range(frag_num):
        idx = j
        j += 1
        if idx == 0x7F:
            j = 1
        if i == frag_num - 1:
            idx |= 0x80
            chunk = data[i * RTL_FRAG_LEN:i * RTL_FRAG_LEN + len(data) % RTL_FRAG_LEN]
        else:
            chunk = data[i * RTL_FRAG_LEN:(i + 1) * RTL_FRAG_LEN]
        out.append(bytes([idx]) + chunk)
    return out


def sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


@dataclass
class RtlInfo:
    lmp_subver: int = 0
    hci_rev: int = 0
    hci_ver: int = 0
    ic: Optional[IcInfo] = None
    rom_version: Optional[int] = None
    key_id: Optional[int] = None
    already_patched: bool = False
    downloaded: int = 0
    fw_file: Optional[str] = None
    cfg_file: Optional[str] = None
    final_version: Optional[tuple] = None
    log: list = field(default_factory=list)


class RtlSetup:
    def __init__(self, hci: Hci, fw_dir: Optional[str] = None, bus: int = HCI_USB):
        self.hci, self.fw_dir, self.bus = hci, fw_dir, bus

    # --- vendor commands
    def read_reg16(self, cmd: bytes) -> bytes:
        r = self.hci.command(OP.RTL_READ_REG16, cmd).fields["ret"]
        if len(r) != 3 or r[0]:
            raise FirmwareError(f"read_reg16 length/status mismatch: {r.hex()}")
        return r[1:3]

    def read_rom_version(self) -> int:
        r = self.hci.command(OP.RTL_READ_ROM_VERSION).fields["ret"]
        if len(r) != 2:
            raise FirmwareError(f"rom version event length mismatch: {r.hex()}")
        return r[1]

    def drop_fw(self) -> None:
        # Linux sends this raw and does not wait for completion.
        self.hci.send_raw_command(OP.RTL_DROP_FW)
        time.sleep(0.2)
        while self.hci.read_event(50) is not None:
            pass

    def download(self, data: bytes) -> int:
        n = 0
        for frag in fragments(data):
            r = self.hci.command(OP.RTL_DOWNLOAD, frag, timeout_s=5.0).fields["ret"]
            if len(r) != 2:
                raise FirmwareError(f"download fw event length mismatch: {r.hex()}")
            n += 1
        return n

    # --- main flow
    def identify(self, info: RtlInfo) -> None:
        dropped = False
        while True:
            try:
                sv = self.read_reg16(RTL_CHIP_SUBVER)
                info.log.append(f"reg16 CHIP_SUBVER={sv.hex()}")
            except (HciError, FirmwareError) as e:  # ROM may not implement it
                info.log.append(f"reg16 CHIP_SUBVER failed: {e}")
            v = self.hci.read_local_version()
            info.lmp_subver, info.hci_rev, info.hci_ver = v.lmp_subver, v.hci_rev, v.hci_ver
            info.ic = match_ic(v.lmp_subver, v.hci_rev, v.hci_ver, self.bus)
            info.log.append(f"examining hci_ver={v.hci_ver:02x} hci_rev={v.hci_rev:04x} "
                            f"lmp_ver={v.lmp_ver:02x} lmp_subver={v.lmp_subver:04x} "
                            f"manufacturer={v.manufacturer}")
            if info.ic is None and not dropped:
                info.log.append("unknown IC (firmware likely already running): sending 0xFC66 drop_fw")
                self.drop_fw()
                dropped = True
                continue
            break
        if info.ic is None:
            info.already_patched = True
            info.log.append("still unknown after drop -> assuming no firmware upload needed")

    def run(self, *, skip_firmware: bool = False) -> RtlInfo:
        info = RtlInfo()
        self.identify(info)
        if info.ic is None:
            return info
        if info.ic.has_rom_version:
            info.rom_version = self.read_rom_version()
            info.log.append(f"rom_version={info.rom_version}")
        try:
            info.key_id = self.read_reg16(RTL_SEC_PROJ)[0]
        except (HciError, FirmwareError) as e:
            info.log.append(f"SEC_PROJ read failed ({e}); assuming key_id=0")
            info.key_id = 0
        info.log.append(f"key_id={info.key_id}")
        if skip_firmware:
            info.log.append("firmware download skipped by request")
            return info
        fw, cfg = self._load_files(info)
        patch = parse_epatch(fw, info.rom_version or 0, info.ic.lmp_subver, info.key_id or 0)
        info.log.append(f"epatch {patch.format} project_id={patch.project_id} "
                        f"fw_version=0x{patch.fw_version:08x} {' '.join(patch.notes)}")
        blob = patch.payload + (cfg or b"")
        info.log.append(f"cfg_sz {len(cfg or b'')}, total sz {len(blob)}")
        info.downloaded = self.download(blob)
        v = self.hci.read_local_version()
        info.final_version = (v.hci_rev, v.lmp_subver)
        info.log.append(f"fw version 0x{v.hci_rev:04x}{v.lmp_subver:04x}")
        return info

    def _load_files(self, info: RtlInfo) -> tuple[bytes, Optional[bytes]]:
        if not self.fw_dir:
            raise FirmwareError("no firmware directory given (use --fw-dir or --skip-fw)")
        fwp = os.path.join(self.fw_dir, info.ic.fw_name + ".bin")
        if not os.path.exists(fwp):
            raise FirmwareError(f"firmware file {fwp} not found (fetch from linux-firmware rtl_bt/)")
        info.fw_file = f"{fwp} sha256={sha256(fwp)}"
        fw = open(fwp, "rb").read()
        cfg = None
        if info.ic.cfg_name and not info.key_id:
            cp = os.path.join(self.fw_dir, info.ic.cfg_name + ".bin")
            if os.path.exists(cp):
                cfg = open(cp, "rb").read()
                info.cfg_file = f"{cp} sha256={sha256(cp)}"
            elif info.ic.config_needed:
                raise FirmwareError(f"mandatory config file {cp} not found")
        return fw, cfg
