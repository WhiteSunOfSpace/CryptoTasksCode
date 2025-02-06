from Cryptodome.Util.number import inverse, long_to_bytes, bytes_to_long

N =
e =
ct =

def find_p_q():
    #code here to find p and q by leak info
    return p, q

p, q = find_p_q()
phi = (p-1)(q-1)
d = inverse(e, phi)

pt = long_to_bytes(pow(ct, d, N))
