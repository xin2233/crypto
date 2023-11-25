from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
import base64

def genkey():
    # 伪随机数生成器
    random_generator = Random.new().read
    # rsa算法生成实例
    rsa = RSA.generate(2048, random_generator)

    # Server的秘钥对的生成
    private_pem = rsa.exportKey()
    with open("server-private.pem", "wb") as f:
        f.write(private_pem)

    public_pem = rsa.publickey().exportKey()
    with open("server-public.pem", "wb") as f:
        f.write(public_pem)

    # Client的秘钥对的生成
    private_pem = rsa.exportKey()
    with open("client-private.pem", "wb") as f:
        f.write(private_pem)

    public_pem = rsa.publickey().exportKey()
    with open("client-public.pem", "wb") as f:
        f.write(public_pem)


message = "hello client, this is a message"
# Server使用Client的公钥对内容进行rsa 加密
def encrypt():


    with open("client-public.pem") as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        cipher_text = base64.b64encode(cipher.encrypt(message.encode('utf-8')))
        print(cipher_text.decode('utf-8'))

# 加密结果：
# HYQPGB + axWCbPp7PPGNTJEAhVPW0TX5ftvUN2v40ChBLB1pS + PVM3YGT5vfcsvmPZhW8NKVSBp8FwjLUnMn6yXP1O36NaunUzyHwI + cpjlkTwZs3DfCY / 32
# EzeuKuJABin1FHBYUMTOKtHy + eEDOuaJTnZTC7ZBkdha + J88HXSc =

# Client使用自己的私钥对内容进行rsa 解密
def decrypt():

    with open("client-private.pem") as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        text = cipher.decrypt(base64.b64decode(encrypt_text), random_generator)
        print(text.decode('utf-8'))

# 解密结果：
# hello
# client, this is a
# message


# Server使用自己的私钥对内容进行签名
def sign():

    with open("server-private.pem") as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        signer = Signature_pkcs1_v1_5.new(rsakey)
        digest = SHA.new()
        digest.update(message)
        sign = signer.sign(digest)
        signature = base64.b64encode(sign)
        print(signature)

# 签名结果：
# jVUcAYfgF5Pwlpgrct3IlCX7KezWqNI5tD5OIFTrfCOQgfyCrOkN + / gRLsMiSDOHhFPj2LnfY4Cr5u4eG2IiH8 + uSF5z4gUX48AqCQlqiOTLk2EGvyp + w + iYo2Bso1MUi424Ebkx7SnuJwLiPqNzIBLfEZLA3ov69aDArh6hQiw =


# Client使用Server的公钥对内容进行验签
def unsign():

    with open("server-public.pem") as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        verifier = Signature_pkcs1_v1_5.new(rsakey)
        digest = SHA.new()
        # Assumes the data is base64 encoded to begin with
        digest.update(message)
        is_verify = signer.verify(digest, base64.b64decode(signature))
        print(is_verify)

# 验签结果：
# True

if __name__ == '__main__':
    genkey()