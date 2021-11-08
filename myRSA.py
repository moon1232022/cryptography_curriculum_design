import base64
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Hash import MD5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
import os
import myMD5


# 生成用户的目录存储路径
def get_userPath(user):
    # 为不同的用户创建不同的公私钥对的存储文件
    user_path = os.path.join(os.path.dirname(__file__), 'USER-'+user)
    if not os.path.exists(user_path):
        os.mkdir(user_path)
    return user_path


# 生成公私钥对
def create_keys(user):
    # 伪随机数生成器
    random_generator = Random.new().read
    # rsa算法生成实例
    rsa = RSA.generate(1024, random_generator)

    # Server的秘钥对的生成
    private_key = rsa.exportKey()
    public_key = rsa.publickey().exportKey()

    # 获取用户的文件存储目录
    user_path = get_userPath(user)
    # 分别将生成的公私钥对存入相关的txt文件中
    privateKeyPath = os.path.join(user_path, user+'-'+"private_key.txt")
    publicKeyPath = os.path.join(user_path, user+'-'+"public_key.txt")

    if not (os.path.exists(privateKeyPath) & os.path.exists(publicKeyPath)):
        with open(privateKeyPath, "wb") as f:
            f.write(private_key)
        with open(publicKeyPath, "wb") as f:
            f.write(public_key)


# 进行数字签名
def sign(data, user):
    user_path = get_userPath(user)
    privateKeyPath = os.path.join(user_path, user+'-'+"private_key.txt")
    digest = myMD5.make_MD5(user, data.encode('utf-8'))

    with open(privateKeyPath) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        signer = PKCS1_v1_5.new(rsakey)
        sign = signer.sign(digest)
        signature = base64.b64encode(sign)
    signaturePath = os.path.join(user_path, user+'-'+'signature.txt')
    with open(signaturePath, 'wb') as fp:
        fp.write(signature)
        return signature


# 验证数字签名
def check_sign(data, signature, sender):
    sender_path = get_userPath(sender)
    publicKeyPath = os.path.join(sender_path, sender+'-'+"public_key.txt")
    digest = MD5.new(data.encode('utf-8'))

    # receiver_path = get_userPath(receiver)
    # signaturePath = os.path.join(receiver_path, receiver + '-' + 'signature.txt')
    # with open(signaturePath) as fp:
    #     signature = base64.b64decode(fp.read())

    with open(publicKeyPath) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        verifier = PKCS1_v1_5.new(rsakey)
        is_verify = verifier.verify(digest, base64.b64decode(signature))
        if is_verify:
            return 'true'
        else:
            return 'error'


# 加密
def encrypt(plaintext, receiver, sender):
    user_path = get_userPath(receiver)
    publicKeyPath = os.path.join(user_path, receiver+'-'+"public_key.txt")

    with open(publicKeyPath) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        # cipherText = PKCS1_OAEP.new(rsakey).encrypt(plaintext.encode('utf-8'))
        cipherText = PKCS1_OAEP.new(rsakey).encrypt(plaintext)

    sender_path = get_userPath(sender)
    cipherTextPath = os.path.join(sender_path, sender+'-'+'RSAciphertext.txt')
    with open(cipherTextPath, 'wb') as fp:
        fp.write(base64.b64encode(cipherText))
    return base64.b64encode(cipherText)


# 解密
def decrypt(user):
    user_path = get_userPath(user)
    cipherTextPath = os.path.join(user_path, user+'-'+'RSAciphertext.txt')
    with open(cipherTextPath) as fp:
        cipherText = base64.b64decode(fp.read())

    privateKeyPath = os.path.join(user_path, user+'-'+"private_key.txt")
    with open(privateKeyPath) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        # plainText = PKCS1_OAEP.new(rsakey).decrypt(cipherText).decode('utf-8')
        plainText = PKCS1_OAEP.new(rsakey).decrypt(cipherText)
    return plainText