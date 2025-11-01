#!/usr/bin/env python3
#
# Credits
# shomy - https://github.com/shomykohai
# bkerler - https://github.com/bkerler

import os
import sys
import struct
from enum import Enum


class DAType(Enum):
    DALegacy = 1
    DAV5 = 2
    DAV6 = 3


# From https://github.com/bkerler/mtkclient/blob/main/Tools/da_parser.py#L95-L103
def is_patched_against_carbonara(da1: bytes) -> bool:
    tests: List[bytes] = [
        b"\x01\x01\x54\xe3\x01\x14\xa0\xe3",
        b"\x08\x00\xa8\x52\xff\x02\x08\xeb",
        b"\x06\x9b\x4f\xf0\x80\x40\x02\xa9",
    ]

    for test in tests:
        if da1.find(test) != -1:
            return True

    return False


def parse_da_loader(loader_path):
    if not os.path.exists(loader_path):
        print("File {loader_path} does not exist.")
        sys.exit(1)
    with open(loader_path, "rb") as bootldr:
        hdr = bootldr.read(0x6C)
        da_type = get_da_type(hdr)
        bootldr.seek(0x68)
        count_da = struct.unpack("<I", bootldr.read(4))[0]

        if da_type == DAType.DALegacy:
            offset = 0xD8
        else:
            offset = 0xDC

        _raw = bootldr.read()

        for i in range(0, count_da):
            bootldr.seek(0x6C + (i * offset))
            data = bootldr.read(offset)
            da = DA(data, da_type, _raw)

            if len(da.region) > 1:
                bootldr.seek(da.region[1].m_buf)
                da1_data = bootldr.read(da.region[1].m_len)
                is_vulnerable = not is_patched_against_carbonara(da1_data)
            else:
                is_vulnerable = False

            return is_vulnerable


def get_da_type(hdr: bytes) -> DAType:
    if b"\xda\xda" in hdr:
        return DAType.DALegacy
    elif b"MTK_DA_v6" in hdr:
        return DAType.DAV6
    return DAType.DAV5


class EntryRegion:
    def __init__(self, data):
        (
            self.m_buf,
            self.m_len,
            self.m_start_addr,
            self.m_start_offset,
            self.m_sig_len,
        ) = struct.unpack("<IIIII", data)

    def __repr__(self):
        return (
            f"Buf: 0x{self.m_buf:08X}, "
            f"Len: 0x{self.m_len:08X}, "
            f"Addr 0x{self.m_start_addr:08X}, "
            f"Offset: 0x{self.m_start_offset:08X}, "
            f"SigLen: 0x{self.m_sig_len:08X}"
        )


class DA:
    def __init__(self, data, da_type: DAType, raw=b""):
        self.da_type = da_type
        self.region = []
        self.magic = struct.unpack("<H", data[0:2])[0]
        self.hw_code = struct.unpack("<H", data[2:4])[0]
        self.hw_sub_code = struct.unpack("<H", data[4:6])[0]
        self.hw_version = struct.unpack("<H", data[6:8])[0]
        idx = 8
        if not da_type == DAType.DALegacy:
            self.sw_version = struct.unpack("<H", data[idx : idx + 2])[0]
            idx += 2
            self.reserved1 = struct.unpack("<H", data[idx : idx + 2])[0]
            idx += 2
        else:
            self.sw_version = 0
            self.reserved1 = 0
        self.pagesize = struct.unpack("<H", data[idx : idx + 2])[0]
        idx += 2
        self.reserved3 = struct.unpack("<H", data[idx : idx + 2])[0]
        idx += 2
        self.entry_region_index = struct.unpack("<H", data[idx : idx + 2])[0]
        idx += 2
        self.entry_region_count = struct.unpack("<H", data[idx : idx + 2])[0]
        idx += 2
        for _ in range(self.entry_region_count):
            entry = EntryRegion(data[idx : idx + 20])
            self.region.append(entry)
            idx += 20
        try:
            self.daentry_magic = data[idx : idx + 2]
            self.chip_id = struct.unpack("<H", data[idx + 2 : idx + 4])[0]
            self.chip_version = struct.unpack("<I", data[idx + 4 : idx + 8])[0]
            self.firmware_version = struct.unpack("<I", data[idx + 8 : idx + 12])[0]
            self.extra_version = struct.unpack("<I", data[idx + 12 : idx + 16])[0]
        except struct.error:
            self.daentry_magic = None
            self.chip_id = None
            self.chip_version = None
            self.firmware_version = None
            self.extra_version = None

    def __repr__(self):
        return (
            f"DA: HWCode: 0x{self.hw_code:04X}, "
            f"HWSubCode: 0x{self.hw_sub_code:04X}, HWVer: 0x{self.hw_version:04X}, "
            f"SWVer: 0x{self.sw_version:04X}, Pagesize: 0x{self.pagesize:X}, "
            f"EntryRegions: {self.entry_region_count}"
        )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 carbonara_checker.py <DA_loader.bin>")
        sys.exit(1)
    loader_path = sys.argv[1]
    parse_da_loader(loader_path)
