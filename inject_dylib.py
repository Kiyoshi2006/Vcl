#!/usr/bin/env python3
"""Thêm một LC_LOAD_DYLIB vào Mach-O arm64 (thin).

Dùng:  inject_dylib.py <macho> <đường-dẫn-dylib-trong-app>
Ví dụ: inject_dylib.py VLC-iOS-no-watch @executable_path/Frameworks/VLCFix.dylib

Chỉ ghi vào khoảng đệm giữa load commands và section đầu tiên; nếu không đủ chỗ thì
gỡ LC_CODE_SIGNATURE (chữ ký sẽ được TrollStore ký lại khi cài) để lấy thêm 16 byte.
"""
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_CODE_SIGNATURE = 0x1D


def align8(n):
    return (n + 7) & ~7


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    path, dylib = sys.argv[1], sys.argv[2]
    data = bytearray(open(path, "rb").read())

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != MH_MAGIC_64:
        print("Không phải Mach-O 64-bit thin (magic=%#x)" % magic)
        return 1

    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    cmds = []  # (cmd, size, offset)
    pos = 32
    min_sect = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, pos)
        cmds.append((cmd, size, pos))
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from("<I", data, pos + 64)[0]
            for s in range(nsects):
                sp = pos + 72 + s * 80
                sect_size = struct.unpack_from("<Q", data, sp + 40)[0]
                sect_off = struct.unpack_from("<I", data, sp + 48)[0]
                if sect_off and sect_size:
                    min_sect = sect_off if min_sect is None else min(min_sect, sect_off)
        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
            name_off = struct.unpack_from("<I", data, pos + 8)[0]
            name = bytes(data[pos + name_off : pos + size]).split(b"\0")[0].decode()
            if name == dylib:
                print("Đã có %s, bỏ qua." % dylib)
                return 0
        pos += size

    end_of_cmds = 32 + sizeofcmds
    if min_sect is None:
        print("Không tìm thấy section nào")
        return 1

    raw = dylib.encode() + b"\0"
    cmdsize = align8(24 + len(raw))
    blob = struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 2, 0x00010000, 0x00010000)
    blob += raw + b"\0" * (cmdsize - 24 - len(raw))

    free = min_sect - end_of_cmds
    print("Chỗ trống sau load commands: %d byte, cần %d byte" % (free, cmdsize))

    if free < cmdsize:
        # gỡ LC_CODE_SIGNATURE (thường là lệnh cuối) để có thêm chỗ
        sig = [c for c in cmds if c[0] == LC_CODE_SIGNATURE]
        if not sig or sig[-1] is not cmds[-1]:
            print("Không đủ chỗ và không gỡ được chữ ký")
            return 1
        cmd, size, off = sig[-1]
        data[off : off + size] = b"\0" * size
        ncmds -= 1
        sizeofcmds -= size
        end_of_cmds -= size
        free = min_sect - end_of_cmds
        print("Đã gỡ LC_CODE_SIGNATURE, chỗ trống mới: %d byte" % free)
        if free < cmdsize:
            print("Vẫn không đủ chỗ")
            return 1

    data[end_of_cmds : end_of_cmds + cmdsize] = blob
    ncmds += 1
    sizeofcmds += cmdsize
    struct.pack_into("<II", data, 16, ncmds, sizeofcmds)
    open(path, "wb").write(data)
    print("OK: đã thêm %s (ncmds=%d)" % (dylib, ncmds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
