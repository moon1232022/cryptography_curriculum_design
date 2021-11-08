from Crypto.Hash import MD5
import os


def get_userPath(user):
    # 为不同的用户创建不同的公私钥对的存储文件
    user_path = os.path.join(os.path.dirname(__file__), 'USER-'+user)
    if not os.path.exists(user_path):
        os.mkdir(user_path)
    return user_path


def make_MD5(user, data):
    digest = MD5.new(data)
    md5 = digest.hexdigest()
    user_path = get_userPath(user)
    MD5Path = os.path.join(user_path, user+'-'+'md5.txt')
    with open(MD5Path, 'w') as fp:
        fp.write(md5)
    return digest


def get_MD5(user):
    user_path = get_userPath(user)
    MD5Path = os.path.join(user_path, user+'-'+'md5.txt')
    with open(MD5Path) as fp:
        md5 = fp.read()
    return md5
