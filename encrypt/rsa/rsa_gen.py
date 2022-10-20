# coding:utf-8
# @file rsa_genkye.py
# @brief Automatic generation of RSA key pair
# @author qzl
# @date 2021.03.10

import binascii
import hashlib
import random
import secrets

# OUT_HEAD_FILE = '../../crypto/rsa_key.c'

OUT_HEAD_FILE = 'rsa_key.c'

prime_min = 0xb504f33400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

ltm_prime_tab = [
    0x0002, 0x0003, 0x0005, 0x0007, 0x000B, 0x000D, 0x0011, 0x0013,
    0x0017, 0x001D, 0x001F, 0x0025, 0x0029, 0x002B, 0x002F, 0x0035,
    0x003B, 0x003D, 0x0043, 0x0047, 0x0049, 0x004F, 0x0053, 0x0059,
    0x0061, 0x0065, 0x0067, 0x006B, 0x006D, 0x0071, 0x007F, 0x0083,

    0x0089, 0x008B, 0x0095, 0x0097, 0x009D, 0x00A3, 0x00A7, 0x00AD,
    0x00B3, 0x00B5, 0x00BF, 0x00C1, 0x00C5, 0x00C7, 0x00D3, 0x00DF,
    0x00E3, 0x00E5, 0x00E9, 0x00EF, 0x00F1, 0x00FB, 0x0101, 0x0107,
    0x010D, 0x010F, 0x0115, 0x0119, 0x011B, 0x0125, 0x0133, 0x0137,

    0x0139, 0x013D, 0x014B, 0x0151, 0x015B, 0x015D, 0x0161, 0x0167,
    0x016F, 0x0175, 0x017B, 0x017F, 0x0185, 0x018D, 0x0191, 0x0199,
    0x01A3, 0x01A5, 0x01AF, 0x01B1, 0x01B7, 0x01BB, 0x01C1, 0x01C9,
    0x01CD, 0x01CF, 0x01D3, 0x01DF, 0x01E7, 0x01EB, 0x01F3, 0x01F7,
    0x01FD, 0x0209, 0x020B, 0x021D, 0x0223, 0x022D, 0x0233, 0x0239,
    0x023B, 0x0241, 0x024B, 0x0251, 0x0257, 0x0259, 0x025F, 0x0265,
    0x0269, 0x026B, 0x0277, 0x0281, 0x0283, 0x0287, 0x028D, 0x0293,
    0x0295, 0x02A1, 0x02A5, 0x02AB, 0x02B3, 0x02BD, 0x02C5, 0x02CF,

    0x02D7, 0x02DD, 0x02E3, 0x02E7, 0x02EF, 0x02F5, 0x02F9, 0x0301,
    0x0305, 0x0313, 0x031D, 0x0329, 0x032B, 0x0335, 0x0337, 0x033B,
    0x033D, 0x0347, 0x0355, 0x0359, 0x035B, 0x035F, 0x036D, 0x0371,
    0x0373, 0x0377, 0x038B, 0x038F, 0x0397, 0x03A1, 0x03A9, 0x03AD,
    0x03B3, 0x03B9, 0x03C7, 0x03CB, 0x03D1, 0x03D7, 0x03DF, 0x03E5,
    0x03F1, 0x03F5, 0x03FB, 0x03FD, 0x0407, 0x0409, 0x040F, 0x0419,
    0x041B, 0x0425, 0x0427, 0x042D, 0x043F, 0x0443, 0x0445, 0x0449,
    0x044F, 0x0455, 0x045D, 0x0463, 0x0469, 0x047F, 0x0481, 0x048B,

    0x0493, 0x049D, 0x04A3, 0x04A9, 0x04B1, 0x04BD, 0x04C1, 0x04C7,
    0x04CD, 0x04CF, 0x04D5, 0x04E1, 0x04EB, 0x04FD, 0x04FF, 0x0503,
    0x0509, 0x050B, 0x0511, 0x0515, 0x0517, 0x051B, 0x0527, 0x0529,
    0x052F, 0x0551, 0x0557, 0x055D, 0x0565, 0x0577, 0x0581, 0x058F,
    0x0593, 0x0595, 0x0599, 0x059F, 0x05A7, 0x05AB, 0x05AD, 0x05B3,
    0x05BF, 0x05C9, 0x05CB, 0x05CF, 0x05D1, 0x05D5, 0x05DB, 0x05E7,
    0x05F3, 0x05FB, 0x0607, 0x060D, 0x0611, 0x0617, 0x061F, 0x0623,
    0x062B, 0x062F, 0x063D, 0x0641, 0x0647, 0x0649, 0x064D, 0x0653]


def fast_power(base, power, n):
    result = 1
    tmp = base
    while power > 0:
        if power & 1 == 1:
            result = (result * tmp) % n
        tmp = (tmp * tmp) % n
        power = power >> 1
    return result


def Miller_Rabin(n, mr_num):
    if n == 2:
        return True
    if n & 1 == 0 or n < 2:
        return False

    m, s = n - 1, 0
    while m & 1 == 0:
        m = m >> 1
        s += 1
    for _ in range(mr_num):
        b = fast_power(random.randint(2, n - 1), m, n)
        if b == 1 or b == n - 1:
            continue
        for __ in range(s - 1):
            b = fast_power(b, 2, n)
            if b == n - 1:
                break
        else:
            return False
    return True


def get_prime(size):
    a = 0
    index = 0
    while 1:
        index += 1
        time = 0
        while (a < prime_min):
            a = secrets.randbits(size)
        a |= 3
        a = a if a % 5 == 0 else a + 2
        while 1:
            time += 1
            next_a = False
            for item in ltm_prime_tab:
                if a % item == 0:
                    next_a = True
                    break
            if not next_a:
                if Miller_Rabin(a, 10):
                    return a
            a = a + 2
            if time > 670:
                break


def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b


def mod_exp(base, exponent, n):
    bin_array = bin(exponent)[2:][::-1]
    r = len(bin_array)
    base_array = []

    pre_base = base
    base_array.append(pre_base)

    for _ in range(r - 1):
        next_base = (pre_base * pre_base) % n
        base_array.append(next_base)
        pre_base = next_base

    res = __multi(base_array, bin_array, n)
    return res % n


def __multi(array, bin_array, n):
    result = 1
    for index in range(len(array)):
        a = array[index]
        if not int(bin_array[index]):
            continue
        result *= a
        result = result % n
    return result


def mod_inv(a, m):
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def gen_key(p, q):
    e = 65537
    n = p * q
    tmp3 = (p - 1) * (q - 1)
    d = mod_inv(e, tmp3)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = mod_inv(q, p)
    # return: pubkey, prikey, prikey_needed(p, q, dp, dq, qinv)
    return (n, e), (n, d), (qinv, dq, dp, q, p)


def encrypt(m, pubkey):
    n = pubkey[0]
    e = pubkey[1]
    c = mod_exp(m, e, n)
    return c


def decrypt(c, prikey):
    n = prikey[0]
    d = prikey[1]
    m = mod_exp(c, d, n)
    return m


# def save_pkcs1(format: str = "PEM") -> bytes:
#     """Saves the key in PKCS#1 DER or PEM format.
#
#     :param format: the format to save; 'PEM' or 'DER'
#     :type format: str
#     :returns: the DER- or PEM-encoded key.
#     :rtype: bytes
#     """
#
#     methods = {
#         "PEM": self._save_pkcs1_pem,
#         "DER": self._save_pkcs1_der,
#     }
#
#     method = self._assert_format_exists(format, methods)
#     return method()


def key_generate(size):
    if size % 8 != 0:
        return -1
    pubkey_str = prikey_str = hash_str = str_tmp = ''
    str_m = "014c04da4ada1d093d07c2b59f5b0eee28224ec15ddb840c9b630c1670465257" \
            "19faa98560027a775c031c6a2aa15147a0891f9f0bab54561cb000684f40598f" \
            "1fcc1595466d694ad33bf75c05b0877438aa119c4a74f0c9092f3c70d99f674e" \
            "ef9384af373e95b37c2572dc35cef707e5c824a611537afc29c7cdc07b972379" \
            "014c04da4ada1d093d07c2b59f5b0eee28224ec15ddb840c9b630c1670465257" \
            "19faa98560027a775c031c6a2aa15147a0891f9f0bab54561cb000684f40598f" \
            "1fcc1595466d694ad33bf75c05b0877438aa119c4a74f0c9092f3c70d99f674e" \
            "ef9384af373e95b37c2572dc35cef707e5c824a611537afc29c7cdc07b972319"
    m = int(str_m, 16)
    while True:
        p = get_prime(size // 2)
        q = get_prime(size // 2)
        # (n, e), (n, d), (qinv, dq, dp, q, p)
        pubkey, prikey1, prikey = gen_key(p, q)

        c = encrypt(m, pubkey)
        d = decrypt(c, prikey1)
        if m == d:
            # hex() 函数用于将10进制整数转换成16进制，以字符串形式表示。
            pubkey_str += hex(pubkey[0])[2:]
            pubkey_str = '0' * (size // 4 - len(pubkey_str)) + pubkey_str

            # when we compute sha512 digest we need turn round str
            pub_temp = turn_round(pubkey_str)
            n_digest = hashlib.sha512(binascii.unhexlify(pub_temp)).hexdigest()
            n_digest = turn_round(n_digest)

            for i in range(len(prikey)):
                str_tmp = hex(prikey[i])[2:]
                str_tmp = '0' * (size // 8 - len(str_tmp)) + str_tmp
                prikey_str += str_tmp
            hash_str += n_digest
            return (pubkey_str, prikey_str, hash_str, (pubkey[0], pubkey[1], prikey1[1], p, q))


# convert str key to arry
def key_convert(str) -> str:
    line = '    0x' + str[-8:] + ','
    for i in range(1, len(str) // 8):
        j = i * 8
        if i % 4 == 0:
            temp = '\n    0x' + str[-8 - j: - j] + ','
        else:
            temp = '0x' + str[-8 - j: - j] + ','
        line = line + temp
    return line


# turn ronud the source to hash
def turn_round(str):
    line = str[-2:]
    for i in range(0, len(str) // 2):
        j = i * 2
        temp = str[-2 - j: - j]

        line = line + temp
    return line


def gen_rsa_key_file(pub_arry, pri_arry, hash_arry):
    head = [
        '/*******************************************************************************\n',
        '* rsa_key.c\n',
        '*\n',
        '* Copyright (C) Sinochip Co.\n',
        '*\n',
        '* Auto generated by python\n',
        '* Don\'t modify it manually!!!\n',
        '*******************************************************************************/\n',
        '\n',
        '\n',
        '#include "rsa_key.h"',
        '\n',
        '\n', ]
    pub_head = [
        '/**\n',
        ' * @brief rsa2048 public key\n',
        ' *\n',
        ' */\n',
        'const u32 g_public_key[64] =\n', ]

    pri_head = [
        '/**\n',
        ' * @brief rsa2048 private key\n',
        ' *\n',
        ' */\n',
        'const u32 g_private_key[160] =\n', ]

    hash_head = [
        '/**\n',
        ' * @brief public key sha512 digest\n',
        ' *\n',
        ' */\n',
        'const u32 g_pub_key_digest[16] =\n', ]
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


if __name__ == "__main__":
    (pubkey_str, prikey_str, hash_str, prikey) = key_generate(2048)
    # convert to arry
    pub_arry = key_convert(pubkey_str)
    pri_arry = key_convert(prikey_str)
    hash_arry = key_convert(hash_str)
    # generate rsa_key.c
    gen_rsa_key_file(pub_arry, pri_arry, hash_arry)

    # generate ras key.bin
    with open('./key/rsa_pub_key_digest.bin', 'wb') as f:
        f.write(bytes.fromhex(turn_round(hash_str)))

    with open('./key/rsa_pub_key.bin', 'wb') as f:
        f.write(bytes.fromhex(turn_round(pubkey_str)))

    with open('./key/rsa_pri_key.bin', 'wb') as f:
        f.write(bytes.fromhex(turn_round(prikey_str)))

    import rsa

    '''
    need to use the following data to instance the publickey and privatekey class
    n = prikey[0],e = prikey[1], d = prikey[2], p = prikey[3], q = prikey[4]
    publickey(n,e)
    privatekey(n,3,d,p,q)
    '''
    pubk = rsa.PublicKey(prikey[0], prikey[1])
    prik = rsa.PrivateKey(prikey[0], prikey[1], prikey[2], prikey[3], prikey[4])

    pub = pubk.save_pkcs1()
    with open('./key/rsa_pub.pem', 'wb+') as f:
        f.write(pub)

    sec = prik.save_pkcs1()
    with open('./key/rsa_pri.pem', 'wb+') as f:
        f.write(sec)
