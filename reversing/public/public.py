import struct
import math

n = 4271010253
e = 201326609

p = 65287
q = 65419

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

with open("out.bin", "rb") as f:
    data = f.read()

flag = b""

for i in range(0, len(data), 8):
    c = struct.unpack("<Q", data[i:i+8])[0]
    m = pow(c, d, n)
    flag += struct.pack("<I", m)

print(flag.decode())