from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import hashlib
from sympy import discrete_log
import math
import random

from sympy import discrete_log


def solve_discrete_log(p, g, A, B):
    a = discrete_log(p, A, g)
    return pow(B, int(a), p)

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


p = "0xde26ab651b92a129"
g = "0x2"
A = "0x3814aa5d17c68d6c"
A = int(A, 0)
p = int(p, 0)
g = int(g, 0)

B = "0x59f74ec046076d0a"
B = int(B, 0)
shared = solve_discrete_log(p, g, A, B)
iv = "752f082df6b08f86ab1fb08292261941"
encrypted_flag = "c4753ba29568348be0c1b8f511e86c57d3eb61deef591e90d885ca659b07c377"

print(decrypt_flag(shared, iv, encrypted_flag))
