def decode(data: bytes) -> bytes:
    out = bytearray()

    prev = -1
    i = 0

    while i < len(data):
        c = data[i]
        i += 1

        out.append(c)

        if c == prev:
            if i >= len(data):
                break

            count = data[i]
            i += 1

            out.extend(bytes([c]) * count)
            prev = -1
        else:
            prev = c

    return bytes(out)


with open("secretMessage.enc", "rb") as f:
    enc = f.read()

raw = decode(enc)

with open("secretMessage.raw", "wb") as f:
    f.write(raw)

print(len(enc))
print(len(raw))