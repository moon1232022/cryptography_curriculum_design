import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os


# 生成用户的目录存储路径
def get_userPath(user):
    # 为不同的用户创建不同的公私钥对的存储文件
    user_path = os.path.join(os.path.dirname(__file__), 'USER-'+user)
    if not os.path.exists(user_path):
        os.mkdir(user_path)
    return user_path


# 随机生成密钥
def create_key(user):
    key = get_random_bytes(16)
    user_path = get_userPath(user)
    key_path = os.path.join(user_path, user+'-'+"DESkey.txt")
    with open(key_path, 'wb') as fp:
        fp.write(base64.b64encode(key))


def get_key(user):
    user_path = get_userPath(user)
    key_path = os.path.join(user_path, user+'-'+"DESkey.txt")
    with open(key_path) as fp:
        key = base64.b64decode(fp.read())
    return key


def encrypt(user, plainText, tp):
    user_path = get_userPath(user)
    key = get_key(user)
    cipher = AES.new(key, AES.MODE_EAX)
    cipher_text = cipher.encrypt(plainText.encode('utf-8'))
    cipherTextPath = os.path.join(user_path, user + '-' + tp + '-' + 'DESciphertext.txt')
    with open(cipherTextPath, 'wb') as fp:
        fp.write(base64.b64encode(cipher_text))

    noncePath = os.path.join(user_path, user + '-' + tp + '-' + 'DESnonce.txt')
    with open(noncePath, 'wb') as fp:
        fp.write(base64.b64encode(cipher.nonce))
    return base64.b64encode(cipher_text), base64.b64encode(cipher.nonce)


def decrypt(user, tp):
    user_path = get_userPath(user)
    key = get_key(user)
    cipherTextPath = os.path.join(user_path, user + '-' + tp + '-' + 'DESciphertext.txt')
    with open(cipherTextPath) as fp:
        cipher_text = base64.b64decode(fp.read())

    noncePath = os.path.join(user_path, user + '-' + tp + '-' + 'DESnonce.txt')
    with open(noncePath) as fp:
        nonce = base64.b64decode(fp.read())

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plain_text = cipher.decrypt(cipher_text).decode('utf-8')
    return plain_text

