from pathlib import Path

def rol16(x, r):
    return ((x << r) | (x >> (16 - r))) & 0xffff

def ror16(x, r):
    return ((x >> r) | (x << (16 - r))) & 0xffff

def decrypt_block(block, key_words):
    x = int.from_bytes(block[0:2], "little")
    y = int.from_bytes(block[2:4], "little")

    for i in range(2, -1, -1):
        x, y = y, x

        x ^= key_words[2 * i]
        y ^= key_words[2 * i + 1]

        y_old = ror16(y, 7)
        x_old = ror16((x - y_old) & 0xffff, 7)

        x, y = x_old, y_old

    return x.to_bytes(2, "little") + y.to_bytes(2, "little")

key = Path("key").read_bytes()
enc = Path("flag.enc").read_bytes()

key_words = []

for i in range(0, len(key), 2):
    key_words.append(int.from_bytes(key[i:i+2], "little"))

flag = b""

for i in range(0, len(enc), 4):
    flag += decrypt_block(enc[i:i+4], key_words)

print(flag.rstrip(b"\x00").decode())