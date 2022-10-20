# coding:utf-8
# @file sm2_genkey.py
# @brief Automatic generation of SM2 key pair and SM3 digest.
# @author zjx
# @date 2021.10.26

import binascii
from math import ceil
from random import SystemRandom

##############################################################################
#
#                            SM3 encryption algorithm
#
##############################################################################

IV = "7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e"
IV = int(IV.replace(" ", ""), 16)
a = []
for i in range(0, 8):
    a.append(0)
    a[i] = (IV >> ((7 - i) * 32)) & 0xFFFFFFFF
IV = a


def out_hex(list1):
    for i in list1:
        print("%08x" % i)
    print("\n")


def rotate_left(a, k):
    k = k % 32
    return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))


T_j = []
for i in range(0, 16):
    T_j.append(0)
    T_j[i] = 0x79cc4519
for i in range(16, 64):
    T_j.append(0)
    T_j[i] = 0x7a879d8a


def FF_j(X, Y, Z, j):
    if 0 <= j and j < 16:
        ret = X ^ Y ^ Z
    elif 16 <= j and j < 64:
        ret = (X & Y) | (X & Z) | (Y & Z)
    return ret


def GG_j(X, Y, Z, j):
    if 0 <= j and j < 16:
        ret = X ^ Y ^ Z
    elif 16 <= j and j < 64:
        # ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
        ret = (X & Y) | ((~ X) & Z)
    return ret


def P_0(X):
    return X ^ (rotate_left(X, 9)) ^ (rotate_left(X, 17))


def P_1(X):
    return X ^ (rotate_left(X, 15)) ^ (rotate_left(X, 23))


def CF(V_i, B_i):
    W = []
    for i in range(16):
        weight = 0x1000000
        data = 0
        for k in range(i * 4, (i + 1) * 4):
            data = data + B_i[k] * weight
            weight = int(weight / 0x100)
        W.append(data)

    for j in range(16, 68):
        W.append(0)
        W[j] = P_1(W[j - 16] ^ W[j - 9] ^ (rotate_left(W[j - 3], 15))
                   ) ^ (rotate_left(W[j - 13], 7)) ^ W[j - 6]
        str1 = "%08x" % W[j]

    W_1 = []

    for j in range(0, 64):
        W_1.append(0)
        W_1[j] = W[j] ^ W[j + 4]
        str1 = "%08x" % W_1[j]

    A, B, C, D, E, F, G, H = V_i
    """
    print "00",
    out_hex([A, B, C, D, E, F, G, H])
    """
    for j in range(0, 64):
        SS1 = rotate_left(((rotate_left(A, 12)) + E +
                           (rotate_left(T_j[j], j))) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ (rotate_left(A, 12))
        TT1 = (FF_j(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF
        TT2 = (GG_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = rotate_left(B, 9)
        B = A
        A = TT1
        H = G
        G = rotate_left(F, 19)
        F = E
        E = P_0(TT2)

        A = A & 0xFFFFFFFF
        B = B & 0xFFFFFFFF
        C = C & 0xFFFFFFFF
        D = D & 0xFFFFFFFF
        E = E & 0xFFFFFFFF
        F = F & 0xFFFFFFFF
        G = G & 0xFFFFFFFF
        H = H & 0xFFFFFFFF

    V_i_1 = []
    V_i_1.append(A ^ V_i[0])
    V_i_1.append(B ^ V_i[1])
    V_i_1.append(C ^ V_i[2])
    V_i_1.append(D ^ V_i[3])
    V_i_1.append(E ^ V_i[4])
    V_i_1.append(F ^ V_i[5])
    V_i_1.append(G ^ V_i[6])
    V_i_1.append(H ^ V_i[7])
    return V_i_1


def hash_msg(msg):
    # print(msg)
    len1 = len(msg)
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    # 56-64, add 64 byte
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64

    for i in range(reserve1, range_end):
        msg.append(0x00)

    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7 - i])

    # print(msg)

    group_count = round(len(msg) / 64)

    B = []
    for i in range(0, group_count):
        B.append(msg[i * 64:(i + 1) * 64])

    V = []
    V.append(IV)
    for i in range(0, group_count):
        V.append(CF(V[i], B[i]))

    y = V[i + 1]
    result = ""
    for i in y:
        result = '%s%08x' % (result, i)
    return result


'''convert string to byte array'''


def str2byte(msg):
    ml = len(msg)
    msg_byte = []
    # If the encrypted object is a string,
    # you must encode() here. Otherwise, it will be not
    msg_bytearray = msg

    for i in range(ml):
        msg_byte.append(msg_bytearray[i])
    return msg_byte


def byte2str(msg):  # convert byte array to string
    ml = len(msg)
    str1 = b""
    for i in range(ml):
        str1 += b'%c' % msg[i]
    return str1.decode('utf-8')


def hex2byte(msg):  # Convert hexadecimal string to byte array
    ml = len(msg)
    if ml % 2 != 0:
        msg = '0' + msg
    ml = int(len(msg) / 2)
    msg_byte = []
    for i in range(ml):
        msg_byte.append(int(msg[i * 2:i * 2 + 2], 16))
    return msg_byte


def byte2hex(msg):  # Convert byte array to hexadecimal string
    ml = len(msg)
    hexstr = ""
    for i in range(ml):
        hexstr = hexstr + ('%02x' % msg[i])
    return hexstr


# Z is the bit string (str) in hexadecimal,
# and klen is the key length (in bytes)
def KDF(Z, klen):
    klen = int(klen)
    ct = 0x00000001
    rcnt = ceil(klen / 32)
    Zin = hex2byte(Z)
    Ha = ""
    for i in range(int(rcnt)):
        msg = Zin + hex2byte('%08x' % ct)
        # print(msg)
        Ha = Ha + hash_msg(msg)
        # print(Ha)
        ct += 1
    return Ha[0: klen * 2]


def sm3_hash(msg, Hexstr=0):
    """
    Encapsulation method, external call
    : param MSG: binary stream (if a string needs to be passed in,
                    encode MSG in str2byte method, otherwise it will not be encoded)
    : param Hexstr: 0
    : Return: 64 bit SM3 encryption result
    """
    if (Hexstr):
        msg_byte = hex2byte(msg)
    else:
        msg_byte = str2byte(msg)
    return hash_msg(msg_byte)


# turn ronud the source to hash, 
# Switch between big and small ends. Unit is byte
def turn_round(str):
    line = str[-2:]
    for i in range(0, len(str) // 2):
        j = i * 2
        temp = str[-2 - j: - j]

        line = line + temp
    return line


##############################################################################
#
#                            SM2 encryption algorithm
#
##############################################################################

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
sm2p256v1 = CurveFp(
    name="sm2p256v1",
    A=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
    B=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
    P=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
    N=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
    Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
    Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
)


# If you want to use the code below, uncomment it and comment out the code above

# This curve corresponds to "test ECC paramters" in gaia/crypto/ecc.c
# sm2p256v1 = CurveFp(
#     name="sm2p256v1",
#     A=0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498,
#     B=0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A,
#     N=0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7,
#     P=0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3,
#     Gx=0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
#     Gy=0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2,
# )


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
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def toJacobian(Xp_Yp):
    Xp, Yp = Xp_Yp
    return (Xp, Yp, 1)


def fromJacobian(Xp_Yp_Zp, P):
    Xp, Yp, Zp = Xp_Yp_Zp
    z = inv(Zp, P)
    return ((Xp * z ** 2) % P, (Yp * z ** 3) % P)


def jacobianDouble(Xp_Yp_Zp, A, P):
    Xp, Yp, Zp = Xp_Yp_Zp
    if not Yp:
        return (0, 0, 0)
    ysq = (Yp ** 2) % P
    S = (4 * Xp * ysq) % P
    M = (3 * Xp ** 2 + A * Zp ** 4) % P
    nx = (M ** 2 - 2 * S) % P
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
            True: str(hex(self.x))[2:],
            False: "{}{}".format(str(hex(self.x))[2:].zfill(64), str(hex(self.y))[2:].zfill(64))
        }.get(compressed)


# OUT_HEAD_FILE = '../../sdk/src/crypto/sm2_key.c'

# OUT_HEAD_FILE_H = '../../sdk/inc/crypto/sm2_key.h'

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


# Move the last half of the string to the front
def key_shift(str):
    str_x = str[0:64]
    str_y = str[64:128]
    # print("str_x:", str_x)
    # print("str_y:", str_y)
    str_result = "{}{}".format(str_y.zfill(64), str_x.zfill(64))
    return str_result


# generate sm2_key.c
def gen_sm2_key_file(pub_arry, pri_arry, hash_arry):
    c_if = [
        '#if (ECC_STD_PARAM == 1)\n'
        '\n',
    ]
    c_else = [
        '#else\n\n',
    ]
    c_end = [
        '#endif\n',
    ]
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
        '#include "sm2_key.h"\n',
        '#include "ecc.h"\n',
        '\n',
    ]
    pub_head = [
        '/**\n',
        ' * @brief SM2 public key\n',
        ' *\n',
        ' */\n',
        'const u32 g_sm2_pub_key[16] =\n',
    ]
    pri_head = [
        '/**\n',
        ' * @brief SM2 private key\n',
        ' *\n',
        ' */\n',
        'const u32 g_sm2_pri_key[8] =\n',
    ]
    hash_head = [
        '/**\n',
        ' * @brief SM2 public key SM3 digest\n',
        ' *\n',
        ' */\n',
        'const u32 g_sm2_pub_key_digest[8] =\n',
    ]
    sm2key_testcurve = [
        '/**\n',
        ' * @brief SM2 public key\n',
        ' *\n',
        ' */\n',
        'const u32 g_sm2_pub_key[16] =\n',
        '{\n',
        '    0x4df2548a,0xe97c04ff,0xa5844495,0x02bb79e2,\n',
        '    0x825be462,0x471bee11,0x8aa0f119,0x0ae4c779,\n',
        '    0xb798e857,0xa9fe0c6b,0xa176d684,0x07353e53,\n',
        '    0x17b7f16f,0x6352a73c,0x8f1cd4e1,0x7c0240f8,\n',
        '};\n',
        '\n',
        '/**\n',
        ' * @brief SM2 private key\n',
        ' *\n',
        ' */\n',
        'const u32 g_sm2_pri_key[8] =\n',
        '{\n',
        '    0x15897263,0x0c23661d,0x171b1b65,0x2a519a55,\n',
        '    0x3dff7979,0x068c8d80,0xbd433c6c,0x128b2fa8,\n',
        '};\n',
        '\n',
        '/**\n',
        ' * @brief SM2 public key SM3 digest\n',
        ' *\n',
        ' */\n',
        'const u32 g_sm2_pub_key_digest[8] =\n',
        '{\n',
        '    0x961e78ea,0x4190a5d1,0xfe4b2d8e,0xd5a7a4ce,\n',
        '    0xedcdffc0,0x6e8f3e3b,0x9e86c8ea,0x97b6f922,\n',
        '};\n',
    ]
    try:
        with open(OUT_HEAD_FILE, 'w') as out:
            out.writelines(head)
            out.writelines(c_if)
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
            out.writelines(c_else)
            out.writelines(sm2key_testcurve)
            out.writelines(c_end)
    except IOError:
        print('open falied\n')


'''
generate sm2_key.h
'''
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
        '\n',
    ]
    pub_head = [
        '/**\n',
        ' * @brief SM2 public key\n',
        ' *\n',
        ' */\n',
        'extern const u32 g_sm2_pub_key[16];\n',
        '\n',
    ]
    pri_head = [
        '/**\n',
        ' * @brief SM2 private key\n',
        ' *\n',
        ' */\n',
        'extern const u32 g_sm2_pri_key[8];\n',
        '\n',
    ]
    hash_head = [
        '/**\n',
        ' * @brief public key SM2 digest\n',
        ' *\n',
        ' */\n',
        'extern const u32 g_sm2_pub_key_digest[8];\n',
        '\n',
        '#endif  // _INC_CRYPTO_SM2_KEY_H_\n',
    ]
    try:
        with open(OUT_HEAD_FILE_H, 'w') as out:
            out.writelines(head)
            out.writelines(pub_head)

            out.writelines(pri_head)

            out.writelines(hash_head)

    except IOError:
        print('open falied\n')


if __name__ == "__main__":
    # priKey = PrivateKey()
    # pubKey = priKey.publicKey()

    # generate string key ,public, private, sm3 hash key
    # pubkey_str = pubKey.toString(compressed=False)
    # prikey_str = priKey.toString()
    pubkey_str = '99cc712e98fece2ee19d776d3ea0dd2596edc1ae15399221450738425ed3a3f0d83f38bde8d9be75017813e086e01cee38ed5cf70306faafa5318c0df322d5f7'
    prikey_str = 'b12f0e547e5529cc6ead1b532b5f1b01aa16d7407b70ac430c7256da485e2b8f'
    hash_str = sm3_hash(binascii.unhexlify(turn_round((pubkey_str.encode()))))

    # Move the last half of the string to the front
    pubkey_shift = key_shift(pubkey_str)
    hash_str_shift = sm3_hash(binascii.unhexlify(
        turn_round((pubkey_shift.encode()))))

    # '''
    # for debug

    print("pubkey:",pubkey_str)
    print("prikey:",prikey_str)
    print("prikey_str.encode():", prikey_str.encode())
    print("hashkey:",hash_str)
    print("pubkey str shift:",pubkey_shift)
    print("hashKey_shift:",hash_str_shift)
    # '''

    # convert to arry
    pub_arry = key_convert(pubkey_shift)
    pri_arry = key_convert(prikey_str)
    hash_arry = key_convert(turn_round(hash_str_shift))

    # generate sm2_key.c
    gen_sm2_key_file(pub_arry, pri_arry, hash_arry)

    '''
    generate sm2_key.h
    # gen_sm2_key_file_h()

    # data = hash_str.to_bytes(1, 'big')
    # data = bytes('zifuchuan1',encoding='utf-8')
    # data = hex(hash_str)
    '''

    # hash string  digest, sm2_pub_key_digest
    hash_bin_file = bytes.fromhex(hash_str_shift)

    with open('sm2_pub_key_digest.bin', 'wb') as f:
        f.write(hash_bin_file)

    with open('sm2_pub_key.bin', 'wb') as f:
        f.write(bytes.fromhex(turn_round(pubkey_shift)))

    with open('sm2_pri_key.bin', 'wb') as f:
        f.write(bytes.fromhex(turn_round(prikey_str)))


