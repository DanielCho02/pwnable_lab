from pathlib import Path

enc = Path("encrypted").read_bytes()
key = bytes.fromhex("deadbeef")

plain = bytearray()

for i, b in enumerate(enc):
    x = (b - 0x13) & 0xff
    x ^= key[i % 4]
    plain.append(x)

Path("flag.png").write_bytes(plain)