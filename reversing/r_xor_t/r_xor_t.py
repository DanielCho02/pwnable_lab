target = b"C@qpl==Bppl@<=pG<>@l>@Blsp<@l@AArqmGr=B@A>q@@B=GEsmC@ArBmAGlA=@q"

tmp = bytes([x ^ 3 for x in target])
tmp = tmp[::-1]
flag_inner = bytes([(x - 0xd) & 0x7f for x in tmp])

print(f"DH{{{flag_inner.decode()}}}")