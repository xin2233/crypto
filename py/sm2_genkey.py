# coding:utf-8
# @file sm2_genkey.py
# @brief Automatic generation of SM2 key pair
# @author zjx
# @date 2021.10.26

from random import SystemRandom
from sm3_hash import sm3_hash, turn_round
import binascii
from math import ceil


class CurveFp:
    def __init__(self, A, B, P, N, Gx, Gy, name):
        self.A = A
        self.B = B
        self.P = P
        self.N = N
        self.Gx = Gx
        self.Gy = Gy
        self.name = name


# This curve corresponds to "standard ECC paramters" in gaia/crypto/ecc.c
# sm2p256v1 = CurveFp(
# 	name="sm2p256v1",
# 	A=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
# 	B=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
# 	P=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
# 	N=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
# 	Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
# 	Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
# )


# If you want to use the code below, uncomment it and comment out the code above

# This curve corresponds to "test ECC paramters" in gaia/crypto/ecc.c
sm2p256v1 = CurveFp(
    name="sm2p256v1",
    A=0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498,
    B=0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A,
    N=0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7,
    P=0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3,
    Gx=0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
    Gy=0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2,
)


def multiply(a, n, N, A, P):
    return fromJacobian(jacobianMultiply(toJacobian(a), n, N, A, P), P)


def add(a, b, A, P):
    return fromJacobian(jacobianAdd(toJacobian(a), toJacobian(b), A, P), P)


def inv(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high//low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def toJacobian(Xp_Yp):
    Xp, Yp = Xp_Yp
    return (Xp, Yp, 1)


def fromJacobian(Xp_Yp_Zp, P):
    Xp, Yp, Zp = Xp_Yp_Zp
    z = inv(Zp, P)
    return ((Xp * z**2) % P, (Yp * z**3) % P)


def jacobianDouble(Xp_Yp_Zp, A, P):
    Xp, Yp, Zp = Xp_Yp_Zp
    if not Yp:
        return (0, 0, 0)
    ysq = (Yp ** 2) % P
    S = (4 * Xp * ysq) % P
    M = (3 * Xp ** 2 + A * Zp ** 4) % P
    nx = (M**2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * Yp * Zp) % P
    return (nx, ny, nz)


def jacobianAdd(Xp_Yp_Zp, Xq_Yq_Zq, A, P):
    Xp, Yp, Zp = Xp_Yp_Zp
    Xq, Yq, Zq = Xq_Yq_Zq
    if not Yp:
        return (Xq, Yq, Zq)
    if not Yq:
        return (Xp, Yp, Zp)
    U1 = (Xp * Zq ** 2) % P
    U2 = (Xq * Zp ** 2) % P
    S1 = (Yp * Zq ** 3) % P
    S2 = (Yq * Zp ** 3) % P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 1)
        return jacobianDouble((Xp, Yp, Zp), A, P)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R ** 2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * Zp * Zq) % P
    return (nx, ny, nz)


def jacobianMultiply(Xp_Yp_Zp, n, N, A, P):
    Xp, Yp, Zp = Xp_Yp_Zp
    if Yp == 0 or n == 0:
        return (0, 0, 1)
    if n == 1:
        return (Xp, Yp, Zp)
    if n < 0 or n >= N:
        return jacobianMultiply((Xp, Yp, Zp), n % N, N, A, P)
    if (n % 2) == 0:
        return jacobianDouble(jacobianMultiply((Xp, Yp, Zp), n // 2, N, A, P), A, P)
    if (n % 2) == 1:
        return jacobianAdd(jacobianDouble(jacobianMultiply((Xp, Yp, Zp), n // 2, N, A, P), A, P), (Xp, Yp, Zp), A, P)


class PrivateKey:
    def __init__(self, curve=sm2p256v1, secret=None):
        self.curve = curve
        self.secret = secret or SystemRandom().randrange(1, curve.N)

    def publicKey(self):
        curve = self.curve
        xPublicKey, yPublicKey = multiply(
            (curve.Gx, curve.Gy), self.secret, A=curve.A, P=curve.P, N=curve.N)
        return PublicKey(xPublicKey, yPublicKey, curve)

    def toString(self):
        return "{}".format(str(hex(self.secret))[2:].zfill(64))


class PublicKey:
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve

    def toString(self, compressed=True):
        return {
            True:  str(hex(self.x))[2:],
            False: "{}{}".format(str(hex(self.x))[2:].zfill(64), str(hex(self.y))[2:].zfill(64))
        }.get(compressed)


OUT_HEAD_FILE = './sm2_key.c'

OUT_HEAD_FILE_H = './sm2_key.h'


# convert str key to arry
def key_convert(str):
    line = '    0x' + str[-8:] + ','
    for i in range(1, len(str) // 8):
        j = i * 8
        if i % 4 == 0:
            temp = '\n    0x' + str[-8 - j: - j] + ','
        else:
            temp = '0x' + str[-8 - j: - j] + ','
        line = line + temp
    return line


# convert pri_str key to arry
def pri_key_convert(str):
    line = '    0x' + str[-8:] + ','
    for i in range(1, len(str) // 8):
        j = i * 8
        if i % 4 == 0:
            temp = '\n    0x' + str[-8 - j: - j] + ','
        else:
            temp = '0x' + str[-8 - j: - j] + ','
        line = line + temp
    return line


#	Move the last half of the string to the front
def key_shift(str):
    str_x = str[0:64]
    str_y = str[64:128]
    # print("str_x:", str_x)
    # print("str_y:", str_y)
    str_result = "{}{}".format(str_y.zfill(64), str_x.zfill(64))
    return str_result


# generate sm2_key.c
def gen_sm2_key_file(pub_arry, pri_arry, hash_arry):

    head = [
        '/*******************************************************************************\n',
        '* sm2_key.c\n',
        '*\n',
        '* Copyright (C) Sinochip Co.\n',
        '*\n',
        '* Auto generated by python\n',
        '* Don\'t modify it manually!!!\n',
        '*******************************************************************************/\n',
        '\n',
        '\n',
        '#include "sm2_key.h"',
        '\n',
        '\n', ]
    pub_head = [
        '/**\n',
        ' * @brief SM2 public key\n',
        ' *\n',
        ' */\n',
        'const u32 g_sm2_pub_key[16] =\n', ]
    pri_head = [
        '/**\n',
        ' * @brief SM2 private key\n',
        ' *\n',
        ' */\n',
        'const u32 g_sm2_pri_key[8] =\n', ]
    hash_head = [
        '/**\n',
        ' * @brief public key SM2 digest\n',
        ' *\n',
        ' */\n',
        'const u32 g_sm2_pub_key_digest[8] =\n', ]
    try:
        with open(OUT_HEAD_FILE, 'w') as out:
            out.writelines(head)
            out.writelines(pub_head)
            out.write('{\n')
            out.write(pub_arry)
            out.write('\n};\n\n')
            out.writelines(pri_head)
            out.write('{\n')
            out.write(pri_arry)
            out.write('\n};\n\n')
            out.writelines(hash_head)
            out.write('{\n')
            out.write(hash_arry)
            out.write('\n};\n\n')
    except IOError:
        print('open falied\n')


# generate sm2_key.h
def gen_sm2_key_file_h():
    head = [
        '/*******************************************************************************\n',
        '* sm2_key.h\n',
        '*\n',
        '* Copyright (C) Sinochip Co.\n',
        '*\n',
        '* Auto generated by python\n',
        '* Don\'t modify it manually!!!\n',
        '*******************************************************************************/\n',
        '\n',
        '\n',
        '#ifndef _INC_CRYPTO_SM2_KEY_H_\n',
        '#define _INC_CRYPTO_SM2_KEY_H_\n',
        '\n',
        '#include "sysdep.h"\n',
        '\n',
        '\n', ]
    pub_head = [
        '/**\n',
        ' * @brief SM2 public key\n',
        ' *\n',
        ' */\n',
        'extern const u32 g_sm2_pub_key[16];\n',
        '\n', ]
    pri_head = [
        '/**\n',
        ' * @brief SM2 private key\n',
        ' *\n',
        ' */\n',
        'extern const u32 g_sm2_pri_key[8];\n',
        '\n', ]
    hash_head = [
        '/**\n',
        ' * @brief public key SM2 digest\n',
        ' *\n',
        ' */\n',
        'extern const u32 g_sm2_pub_key_digest[8];\n',
        '\n',
        '#endif  // _INC_CRYPTO_SM2_KEY_H_\n', ]
    try:
        with open(OUT_HEAD_FILE_H, 'w') as out:
            out.writelines(head)
            out.writelines(pub_head)

            out.writelines(pri_head)

            out.writelines(hash_head)

    except IOError:
        print('open falied\n')


if __name__ == "__main__":
    priKey = PrivateKey()
    pubKey = priKey.publicKey()

    # generate string key ,public, private, sm3 hash key
    pubkey_str = pubKey.toString(compressed=False)
    prikey_str = priKey.toString()
    hash_str = sm3_hash(binascii.unhexlify(turn_round((pubkey_str.encode()))))

    # Move the last half of the string to the front
    pubkey_shift = key_shift(pubkey_str)
    hash_str_shift = sm3_hash(binascii.unhexlify(
        turn_round((pubkey_shift.encode()))))

    '''
    for debug
    print("pubkey:",pubkey_str)
    print("prikey:",prikey_str)
    print("prikey_str.encode():", prikey_str.encode())
    print("hashkey:",hash_str)
    print("pubkey str shift:",pubkey_shift)
    '''
    # convert to arry
    pub_arry = key_convert(pubkey_shift)
    pri_arry = key_convert(prikey_str)
    hash_arry = key_convert(turn_round(hash_str_shift))

    # generate sm2_key.c
    gen_sm2_key_file(pub_arry, pri_arry, hash_arry)

    # generate sm2_key.h
    gen_sm2_key_file_h()
