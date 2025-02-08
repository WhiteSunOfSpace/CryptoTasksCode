from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import hashlib

def addtition(P, Q, p):  #P, Q - points of curve, p - modulo
    if P is None:
        return Q
    if Q is None:
        return P
    xp, yp = P
    xq, yq = Q
    if ((xp%p) == (xq%p)) and ((yp%p) == (-yq%p)):
        print("0")
    if ((xp%p) != (xq%p)) and ((yp%p) != (-yq%p)):
        m = ((yq - yp) * pow(xq-xp, -1, p)) % p
    else:
        m = ((3*xp*xp + 497) * pow(2*yp, -1, p)) % p #497 - a coeff in elliptic curve
    x3 = (m*m - xp - xq) % p
    y3 = (m*(xp-x3) - yp)%p
    return x3, y3

def multy(base, n, p):  #base - point, n - times of multiplying, p - modulo
    Q = base
    R = None
    while n > 0:
        if n % 2 == 1:
            R = addtition(R, Q, p)
            n -= 1
        else:
            Q = addtition(Q, Q, p)
            n = n//2
    return R

def add_mont(P, Q):
    x1, y1 = P
    x2, y2 = Q
    m = (y2-y1)*inverse(x2-x1, p) % p
    x3 = ((B*m*m)-A-x1-x2) % p
    y3 = (m*(x1-x3)-y1) % p
    return x3, y3

def doub_mont(P):
    x, y = P
    m = (((3*x*x) + (2*A*x) + 1)*inverse(2*B*y, p)) % p
    x3 = (B*m*m-A-2*x) % p
    y3 = (m*(x-x3)-y) % p
    return x3, y3

def mult_mont(P, k):
    R0, R1 = P, doub_mont(P)
    n = k.bit_length()
    for i in range(n-2, -1, -1):
        b = k & (1 << i)
        R0, R1 = (add_mont(R0, R1), doub_mont(R1)) if b != 0 else (doub_mont(R0), add_mont(R0, R1))
    return R0
  
def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))

def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

iv = "hex"
encrypted_flag = "hex"
shared = ?
print(decrypt_flag(shared, iv, encrypted_flag))
