#!/usr/bin/env python3
"""
This script was AI generated as I dont know shit about python
I can confirm it works, thats about it
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Union


SUPPORTED_BUILDS = {
    "bcdboot.exe": {
        "415ca8c856a2336f6fad3a84f44d9e25cc593aafcbea4d5e70478480836ac148": {
            "label": "Windows 8 DP 6.2.8102.0 x86",
            "output": "c668dabb7c89a43cf47935c48b17319cae6e8f927508d0422b411a8dfa82fa41",
        },
    },
    "wimgapi.dll": {
        "bdc0da45afc830fdebda4475e988bd511c0e1ca8d35563f0f6e189f0374db1a9": {
            "label": "Windows 7 6.1.7601.24546 x86",
            "output": "5cf9fd71c88e200244cd35566c819e915a61e1d53e9326cc602cc67f2c0ef6de",
        },
        "01d5535cb22991309fedaba85f1a55e6605d0f1cfb3d0b464d32e1ff31b4ba32": {
            "label": "Windows 7 6.1.7601.17514 x86",
            "output": "87bbd01704e5eb9f36f1c1887819c8d088c8188682e107a6d5d122b1b1a82ed3",
        },
    },
}


def sha256(data):
    # type: (Union[bytes, bytearray]) -> str
    return hashlib.sha256(data).hexdigest()


class PE32:
    def __init__(self, data):
        # type: (bytearray) -> None
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not a DOS/PE executable")
        self.pe_offset = self.u32(0x3C)
        if data[self.pe_offset:self.pe_offset + 4] != b"PE\0\0":
            raise ValueError("invalid PE signature")

        file_header = self.pe_offset + 4
        self.section_count = self.u16(file_header + 2)
        optional_size = self.u16(file_header + 16)
        self.optional = file_header + 20
        if self.u16(self.optional) != 0x10B:
            raise ValueError("only 32-bit PE images are supported")

        self.checksum_offset = self.optional + 64
        self.data_directories = self.optional + 96
        self.size_of_headers = self.u32(self.optional + 60)
        section_table = self.optional + optional_size
        self.sections = []  # type: List[Tuple[int, int, int, int]]
        for index in range(self.section_count):
            entry = section_table + index * 40
            virtual_size = self.u32(entry + 8)
            virtual_address = self.u32(entry + 12)
            raw_size = self.u32(entry + 16)
            raw_offset = self.u32(entry + 20)
            self.sections.append((virtual_address, virtual_size, raw_offset, raw_size))

    def u16(self, offset):
        # type: (int) -> int
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset):
        # type: (int) -> int
        return struct.unpack_from("<I", self.data, offset)[0]

    def set_u16(self, offset, value):
        # type: (int, int) -> None
        struct.pack_into("<H", self.data, offset, value)

    def set_u32(self, offset, value):
        # type: (int, int) -> None
        struct.pack_into("<I", self.data, offset, value)

    def directory(self, index):
        # type: (int) -> Tuple[int, int]
        offset = self.data_directories + index * 8
        return self.u32(offset), self.u32(offset + 4)

    def clear_directory(self, index):
        # type: (int) -> None
        offset = self.data_directories + index * 8
        self.data[offset:offset + 8] = b"\0" * 8

    def set_subsystem_version(self, major, minor):
        # type: (int, int) -> None
        self.set_u16(self.optional + 48, major)
        self.set_u16(self.optional + 50, minor)

    def rva_to_offset(self, rva):
        # type: (int) -> int
        if rva < self.size_of_headers:
            return rva
        for virtual_address, virtual_size, raw_offset, raw_size in self.sections:
            extent = max(virtual_size, raw_size)
            if virtual_address <= rva < virtual_address + extent:
                delta = rva - virtual_address
                if delta >= raw_size:
                    break
                return raw_offset + delta
        raise ValueError("RVA 0x%08X is not backed by file data" % rva)

    def c_string(self, offset):
        # type: (int) -> bytes
        end = self.data.find(0, offset)
        if end < 0:
            raise ValueError("unterminated string in PE image")
        return bytes(self.data[offset:end])

    def replace_c_string(self, offset, expected, replacement):
        # type: (int, bytes, bytes) -> None
        actual = self.c_string(offset)
        if actual.lower() != expected.lower():
            raise ValueError(
                "expected %r at file offset 0x%X, found %r" %
                (expected, offset, actual)
            )
        if len(replacement) > len(actual):
            raise ValueError("replacement DLL name does not fit")
        self.data[offset:offset + len(actual)] = replacement.ljust(len(actual), b"\0")

    def import_descriptors(self):
        # type: () -> List[int]
        import_rva, import_size = self.directory(1)
        if import_rva == 0 or import_size < 20:
            raise ValueError("PE image has no import directory")
        offset = self.rva_to_offset(import_rva)
        descriptors = []
        while any(self.data[offset:offset + 20]):
            descriptors.append(offset)
            offset += 20
        return descriptors

    def update_checksum(self):
        # type: () -> None
        self.set_u32(self.checksum_offset, 0)
        total = 0
        for offset in range(0, len(self.data) - 1, 2):
            total += self.u16(offset)
            total = (total & 0xFFFF) + (total >> 16)
        if len(self.data) & 1:
            total += self.data[-1]
            total = (total & 0xFFFF) + (total >> 16)
        total = (total & 0xFFFF) + (total >> 16)
        total += total >> 16
        total &= 0xFFFF
        total += len(self.data)
        self.set_u32(self.checksum_offset, total & 0xFFFFFFFF)


def replace_import_names(pe, replacements):
    # type: (PE32, Dict[bytes, bytes]) -> None
    changed_names = set()
    for descriptor in pe.import_descriptors():
        name_offset = pe.rva_to_offset(pe.u32(descriptor + 12))
        old_name = pe.c_string(name_offset)
        replacement = replacements.get(old_name.lower())
        if replacement is not None:
            pe.replace_c_string(name_offset, old_name, replacement)
            changed_names.add(old_name.lower())
    if changed_names != set(replacements):
        missing = sorted(
            name.decode("ascii") for name in set(replacements) - changed_names
        )
        raise ValueError("expected imports were not found: %s" % ", ".join(missing))


def restore_unbound_iat(pe):
    # type: (PE32) -> None
    for descriptor in pe.import_descriptors():
        original_thunk = pe.u32(descriptor)
        first_thunk = pe.u32(descriptor + 16)
        if original_thunk == 0:
            raise ValueError("bound image has an import without OriginalFirstThunk")
        source = pe.rva_to_offset(original_thunk)
        target = pe.rva_to_offset(first_thunk)
        index = 0
        while True:
            value = pe.u32(source + index * 4)
            pe.set_u32(target + index * 4, value)
            index += 1
            if value == 0:
                break
        pe.data[descriptor + 4:descriptor + 12] = b"\0" * 8


def rewrite_and_clear_bound_imports(pe, replacements):
    # type: (PE32, Dict[bytes, bytes]) -> None
    bound_rva, bound_size = pe.directory(11)
    if bound_rva == 0 or bound_size < 8:
        raise ValueError("PE image has no bound import directory")
    bound_base = pe.rva_to_offset(bound_rva)
    offset = bound_base
    changed_names = set()
    while True:
        timestamp, name_relative, forwarder_count = struct.unpack_from(
            "<IHH", pe.data, offset
        )
        if timestamp == 0 and name_relative == 0 and forwarder_count == 0:
            break
        name_offset = bound_base + name_relative
        old_name = pe.c_string(name_offset)
        replacement = replacements.get(old_name.lower())
        if replacement is not None:
            pe.replace_c_string(name_offset, old_name, b"ntapi" + old_name[-4:])
            changed_names.add(old_name.lower())
        offset += 8 + forwarder_count * 8
    if changed_names != set(replacements):
        missing = sorted(
            name.decode("ascii") for name in set(replacements) - changed_names
        )
        raise ValueError("expected bound imports were not found: %s" % ", ".join(missing))
    pe.clear_directory(11)


def patch_bcdboot(data):
    # type: (bytearray) -> None
    pe = PE32(data)
    replacements = {
        b"kernel32.dll": b"NTAPI.dll",
        b"ntdll.dll": b"NTAPI.dll",
        b"advapi32.dll": b"ntapi.dll",
    }
    replace_import_names(pe, replacements)
    restore_unbound_iat(pe)
    rewrite_and_clear_bound_imports(pe, replacements)
    pe.set_subsystem_version(4, 0)
    pe.update_checksum()


def patch_wimgapi(data):
    # type: (bytearray) -> None
    pe = PE32(data)
    replacements = {
        b"kernel32.dll": b"NTAPI.dll",
        b"advapi32.dll": b"NTAPI.dll",
    }

    # Reproduce the checked-in binary's patch order: lower the subsystem and
    # update its checksum before editing imports. User-mode DLL loading does
    # not require a valid PE checksum, so the later import edits are retained
    # byte-for-byte without updating this field a second time.
    pe.set_subsystem_version(4, 0)
    pe.update_checksum()
    replace_import_names(pe, replacements)

    bound_rva, bound_size = pe.directory(11)
    if bound_rva != 0 or bound_size != 0:
        if bound_rva == 0 or bound_size < 8:
            raise ValueError("invalid bound import directory")
        restore_unbound_iat(pe)
        rewrite_and_clear_bound_imports(pe, replacements)


def find_build(name, source_hash):
    build = SUPPORTED_BUILDS[name].get(source_hash)
    if build is not None:
        return build
    expected = "; ".join(
        "%s (%s)" % (digest, details["label"])
        for digest, details in SUPPORTED_BUILDS[name].items()
    )
    raise ValueError(
        "unsupported %s SHA-256 %s; accepted sources: %s" %
        (name, source_hash, expected)
    )


def prepare(source, destination, name):
    data = bytearray(source.read_bytes())
    source_hash = sha256(data)
    build = find_build(name, source_hash)
    if name == "bcdboot.exe":
        patch_bcdboot(data)
    else:
        patch_wimgapi(data)
    output_hash = sha256(data)
    if output_hash != build["output"]:
        raise ValueError(
            "internal verification failed for %s: got %s, expected %s" %
            (name, output_hash, build["output"])
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    print("Prepared %s from %s" % (destination, build["label"]))
    print("SHA-256: %s" % output_hash)


def verify_source(source, name):
    source_hash = sha256(source.read_bytes())
    build = find_build(name, source_hash)
    print("Accepted %s (%s)" % (source, build["label"]))


def verify_existing(path, name):
    actual = sha256(path.read_bytes())
    for build in SUPPORTED_BUILDS[name].values():
        if actual == build["output"]:
            print("Verified %s (%s)" % (path, build["label"]))
            print("SHA-256: %s" % actual)
            return
    accepted = "; ".join(
        "%s (%s)" % (build["output"], build["label"])
        for build in SUPPORTED_BUILDS[name].values()
    )
    raise ValueError(
        "%s has SHA-256 %s; accepted patched outputs: %s" %
        (path, actual, accepted)
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Reproduce or verify Rufus-NT's patched legacy bcdboot and "
            "wimgapi binaries."
        )
    )
    parser.add_argument("--bcdboot", type=Path, help="original Microsoft bcdboot.exe")
    parser.add_argument("--wimgapi", type=Path, help="original Microsoft wimgapi.dll")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("res/wintogo"),
        help="destination directory (default: res/wintogo)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="verify the patched files already present in --output-dir",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        if args.verify_only:
            verify_existing(args.output_dir / "bcdboot.exe", "bcdboot.exe")
            verify_existing(args.output_dir / "wimgapi.dll", "wimgapi.dll")
            return 0
        if args.bcdboot is None or args.wimgapi is None:
            raise ValueError(
                "--bcdboot and --wimgapi are required unless --verify-only is used"
            )
        verify_source(args.bcdboot, "bcdboot.exe")
        verify_source(args.wimgapi, "wimgapi.dll")
        prepare(args.bcdboot, args.output_dir / "bcdboot.exe", "bcdboot.exe")
        prepare(args.wimgapi, args.output_dir / "wimgapi.dll", "wimgapi.dll")
        return 0
    except (OSError, ValueError, struct.error) as error:
        print("error: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
