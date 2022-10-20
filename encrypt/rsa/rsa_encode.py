import argparse
import rsa
import hashlib
import os

'''
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

'''
# 其它python3版本使用此方法
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

def create_data():
    '''生成key'''
    (pub_key, sec_key) = rsa.newkeys(2048)
    pub = pub_key.save_pkcs1()
    file = open('./pub.pem', 'wb+')
    file.write(pub)
    sec = sec_key.save_pkcs1()
    files = open('./sec.pem', 'wb+')
    files.write(sec)
    files.close()
    file.close()
    return


def verify_encrypt_rsa(pubpath: str, pripath: str, message:bytes):
    '''
    使用key 来加密【通过公钥】 解密文件【通过私钥】
    '''
    file = open(pubpath, 'rb')
    file1 = open(pripath, 'rb')
    content = file.read()
    # print(content)

    content1 = file1.read()
    # print(content1)
    pub_key = rsa.PublicKey.load_pkcs1(content)
    pri_key = rsa.PrivateKey.load_pkcs1(content1)
    # message = '今天的天气有点热，但整体还是很好'
    data = rsa.encrypt(message, pub_key)
    # print(data)
    result = rsa.decrypt(data, pri_key)
    # print(f"result:\n{bytes.hex(result)}")
    if result == message:
        print('Success:rsa encrypt')

    file.close()
    file1.close()
    return


def verify_signure_rsa(pubpath: str, pripath: str, message:bytes):
    '''
    使用私钥进行签名，使用公钥进行验签
    '''
    file = open(pubpath, 'rb')
    file1 = open(pripath, 'rb')
    content = file.read()
    # print(content)
    content1 = file1.read()
    # print(content1)

    pub_key = rsa.PublicKey.load_pkcs1(content)
    pri_key = rsa.PrivateKey.load_pkcs1(content1)
    # message = '今天的天气有点热，但整体还是很好'
    data = rsa.sign(message, pri_key, 'SHA-512')
    # print('--\n',data)
    result = rsa.verify(message, data, pub_key)
    print('result:\n', result)
    print('Success:rsa sign')
    file.close()
    file1.close()
    return


if __name__ == "__main__":
    # 获取参数
    parser = argparse.ArgumentParser(description="rsa encode of argparse")
    parser.add_argument('-k1', dest='pri_key', help='private key')
    parser.add_argument('-k2', dest='pub_key', help='public key')
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
        # exit()
        encode_file = ''
    if pri_file is None:
        pri_file = './key/rsa_pri.pem'
    if pub_file is None:
        pub_file = './key/rsa_pub.pem'
    if pub_digest_file is None:
        pub_digest_file = './key/rsa_pub_key_digest.bin'

    digest_hash_str = file_sha512(encode_file)
    digest_hash = bytes.fromhex(digest_hash_str)  # 16进制
    print('--')
    print('digest hash str:', digest_hash_str)
    # encode file, use rsa
    verify_encrypt_rsa(pubpath=pub_file, pripath=pri_file, message=digest_hash)

    # sign file
    verify_signure_rsa(pubpath=pub_file, pripath=pri_file, message=digest_hash)
