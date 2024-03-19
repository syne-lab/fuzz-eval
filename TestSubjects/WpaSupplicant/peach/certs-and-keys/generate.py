import hashlib
import math

M = b"hello world!"

N_len = 2048 // 8
N = 0xE932AC92252F585B3A80A4DD76A897C8B7652952FE788F6EC8DD640587A1EE5647670A8AD4C2BE0F9FA6E49C605ADF77B5174230AF7BD50E5D6D6D6D28CCF0A886A514CC72E51D209CC772A52EF419F6A953F3135929588EBE9B351FCA61CED78F346FE00DBB6306E5C2A4C6DFC3779AF85AB417371CF34D8387B9B30AE46D7A5FF5A655B8D8455F1B94AE736989D60A6F2FD5CADBFFBD504C5A756A2E6BB5CECC13BCA7503F6DF8B52ACE5C410997E98809DB4DC30D943DE4E812A47553DCE54844A78E36401D13F77DC650619FED88D8B3926E3D8E319C80C744779AC5D6ABE252896950917476ECE5E8FC27D5F053D6018D91B502C4787558A002B9283DA7

e = 3

d = 0x009b771db6c374e59227006de8f9c5ba85cf98c63754505f9f30939803afc1498eda44b1b1e32c7eb51519edbd9591ea4fce0f8175ca528e09939e48f37088a07059c36332f74368c06884f718c9f8114f1b8d4cb790c63b09d46778bfdc41348fb4cd9feab3d24204992c6dd9ea824fbca591cd64cf68a233ad0526775c9848fafa31528177e1f8df9181a8b945081106fd58bd3d73799b229575c4f3b29101a03ee1f05472b3615784d9244ce0ed639c77e8e212ab52abddf4a928224b6b6f74b7114786dd6071bd9113d7870c6b52c0bc8b9c102cfe321dac357e030ed6c580040ca41c13d6b4967811807ef2a225983ea9f88d67faa42620f42a4f5bdbe03b

hM = hashlib.sha1(M).hexdigest()
sig_prefix = '3025300d06052b0e03021a0601010102030414'
content_len = len(sig_prefix) // 2 + len(hM) // 2
extra_padding_len = N_len - 11 - content_len

print('content_len =', content_len)

tbs = "0x" \
    + "00" \
    + "01" \
    + "FF" * 8 \
    + "FF" * extra_padding_len \
    + "00" \
    + sig_prefix \
    + hM
print('tbs =', tbs)

S = pow(int(tbs, 16), d, N)

# print("   m1 =", hex(m1))
# print("S % p =", hex(S % p))
# print("   m2 =", hex(m2))
# print("S % q =", hex(S % q))

print('S =',hex(S))

sig_bytes = S.to_bytes(256, byteorder='big')
for i in sig_bytes:
    print(hex(i)+', ', end='')

# print('S^e mod p =',hex( pow(S, e, p) ))
# print('tbs mod p =',hex( tbsi % p ))

# print("p =", hex( math.gcd(pow(S, e, N) - tbsi, N) ))

# # print('S^e mod N =',hex( pow(S, e, N) ))

# print('qinv =', qinv)
# print("h =", h)
# print("sq =", m2)