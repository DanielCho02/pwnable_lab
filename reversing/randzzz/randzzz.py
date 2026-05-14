import struct

def get_flag(a1, a2):
    if chr(a1).isdigit():
        v4 = (8 * a1) % 10
        if v4 <= 7 or v4 > 9:
            return (v4 + 50) & 0xff
        else:
            return (v4 + 40) & 0xff
    else:
        v3 = ((a1 << (8 - a2)) | (a1 >> a2))
        return v3 & 0xff

v6 = struct.pack("<QQQi",
    0x386C2C39364C396C,
    0x30383338AC4C4C39,
    0x353330354CCCCC34,
    -865323092
)

v4 = struct.pack("<QQQ",
    0x1B323838330B1335,
    0x0B332323361B2333,
    0x23391B0B38370B13
) + b"3539458369+8"

part1 = bytes(get_flag(c, 5) for c in v6)
part2 = bytes(get_flag(c, 3) for c in v4)

print(b"DH{" + part1 + part2 + b"}")