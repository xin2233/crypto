from sm2_genkey import turn_round, key_shift
from gmssl import sm2, func

import os
import hashlib

# 使用python3.8及以上可以用此方法，写法更简洁。
def file_hash(file_path: str, hash_method) -> str:
    if not os.path.isfile(file_path):
        print('文件不存在。')
        return ''
    h = hash_method()
    with open(file_path, 'rb') as f:
        while b := f.read(8192):
            h.update(b)
    return h.hexdigest()


# 其它python3版本使用此方法
'''
def file_hash(file_path: str, hash_method) -> str:
    if not os.path.isfile(file_path):
        print('文件不存在。')
        return ''
    h = hash_method()
    with open(file_path, 'rb') as f:
        while True:
            b = f.read(8192)
            if not b:
                break	
            h.update(b)
    return h.hexdigest()
'''


def str_hash(content: str, hash_method, encoding: str = 'UTF-8') -> str:
    return hash_method(content.encode(encoding)).hexdigest()


def file_md5(file_path: str) -> str:
    return file_hash(file_path, hashlib.md5)


def file_sha256(file_path: str) -> str:
    return file_hash(file_path, hashlib.sha256)


def file_sha512(file_path: str) -> str:
    return file_hash(file_path, hashlib.sha512)


def file_sha384(file_path: str) -> str:
    return file_hash(file_path, hashlib.sha384)


def file_sha1(file_path: str) -> str:
    return file_hash(file_path, hashlib.sha1)


def file_sha224(file_path: str) -> str:
    return file_hash(file_path, hashlib.sha224)


def str_md5(content: str, encoding: str = 'UTF-8') -> str:
    return str_hash(content, hashlib.md5, encoding)


def str_sha256(content: str, encoding: str = 'UTF-8') -> str:
    return str_hash(content, hashlib.sha256, encoding)


def str_sha512(content: str, encoding: str = 'UTF-8') -> str:
    return str_hash(content, hashlib.sha512, encoding)


def str_sha384(content: str, encoding: str = 'UTF-8') -> str:
    return str_hash(content, hashlib.sha384, encoding)


def str_sha1(content: str, encoding: str = 'UTF-8') -> str:
    return str_hash(content, hashlib.sha1, encoding)


def str_sha224(content: str, encoding: str = 'UTF-8') -> str:
    return str_hash(content, hashlib.sha224, encoding)


import argparse

if __name__ == "__main__":

    '''
    读取sm2gen.py 生成的key文件， 验证key 是否正确
    usage: python3 xx.py -k1 [pri_key] -k2 [pub key] -k3 [encode file] -k4 [public digest key]
    '''

    # 获取参数
    parser = argparse.ArgumentParser(description="sm2 encode of argparse")
    parser.add_argument('-k1', dest='pri_key', required=True, help='private key')
    parser.add_argument('-k2', dest='pub_key', help='public key', required=True)
    parser.add_argument('-k3', dest='en_file', help='encode file', required=True)
    parser.add_argument('-k4', dest='pub_digest_key', help='public digest key file', required=False)
    args = parser.parse_args()
    # print(args)
    encode_file = args.en_file
    pri_file = args.pri_key
    pub_file = args.pub_key
    pub_digest_file = args.pub_digest_key

    # print('encode file,', encode_file)
    if encode_file is None:
        print('Error: parameters error, please -h to show help!')
        exit()
    if pri_file is None:
        pri_file = 'sm2_pri_key.bin'
    if pub_file is None:
        pub_file = 'sm2_pub_key.bin'
    if pub_digest_file is None:
        pub_digest_file = 'sm2_pub_key_digest.bin'

    '''
    encode file, use sm2
    '''
    # sm2 pri key
    # b12f0e547e5529cc6ead1b532b5f1b01aa16d7407b70ac430c7256da485e2b8f
    # sm2 pub key
    # 99cc712e98fece2ee19d776d3ea0dd2596edc1ae15399221450738425ed3a3f0d83f38bde8d9be75017813e086e01cee38ed5cf70306faafa5318c0df322d5f7

    # get sm2 public key
    with open(pri_file, 'rb') as f:
        sm2_pri_key_bin = f.read(32)

    with open(pub_file, 'rb') as f:
        sm2_pub_key_bin = f.read(64)

    with open(pub_digest_file, 'rb') as f:
        sm2_pub_key_digest_bin = f.read(32)

    sm2_pri_key_str_turn = bytes.hex(sm2_pri_key_bin)
    sm2_pri_key_str = turn_round(sm2_pri_key_str_turn)
    print('sm2 private key :', sm2_pri_key_str)

    sm2_pub_key_str_turn = bytes.hex(sm2_pub_key_bin)
    sm2_pub_key_str = key_shift(turn_round(sm2_pub_key_str_turn))
    print('sm2 pub key str:', sm2_pub_key_str)

    sm2_pub_key_digest_str_shift = bytes.hex(sm2_pub_key_digest_bin)
    sm2_pub_key_digest_str = turn_round(sm2_pub_key_digest_str_shift)
    print('sm2 pub key digest str:', sm2_pub_key_digest_str)

    print('开始加密数据'.center(16, '='))

    sm2_crypt = sm2.CryptSM2(public_key=sm2_pub_key_str, private_key=sm2_pri_key_str)

    '''
    # 加密数据
    data = b"111"
    enc_data = sm2_crypt.encrypt(data)
    dec_data = sm2_crypt.decrypt(enc_data)
    print('---encdata,', enc_data.hex())
    print('---decdata,', dec_data.hex())
    assert dec_data == data
    '''

    # 签名验签
    digest_hash_str = file_sha512('sm2_pub_key_digest.bin')
    digest_hash = bytes.fromhex(digest_hash_str)  # 16进制
    print('--')
    print('digest hash str:', digest_hash_str)

    random_hex_str = func.random_hex(sm2_crypt.para_len)
    sign = sm2_crypt.sign(digest_hash, random_hex_str)  # 16进制
    print(f"sign:\n{sign}")
    print('-----')
    assert sm2_crypt.verify(sign, digest_hash)

    # 保存签名文件
    with open('sm2_sign.bin','wb') as f:
        f.write(bytes.fromhex(sign))  # str -> hex
        print('write done')

