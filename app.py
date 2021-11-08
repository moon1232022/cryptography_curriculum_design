import base64
import myRSA
import myDES
import myMD5
from flask import Flask, request
from flask_cors import CORS
import os

app = Flask(__name__)
cors = CORS(app, resources={'/*': {'origins': '*'}})


@app.route('/')
def hello():
    return 'hello'


@app.route('/createRSAKey', methods=['GET', 'POST'])
def createRSAKey():
    if request.method == 'GET':
        user = request.args['user']
        myRSA.create_keys(user)
        return 'successfully created'


@app.route('/createDESKey', methods=['GET', 'POST'])
def createDESKey():
    if request.method == 'GET':
        sender = request.args['user']
        myDES.create_key(sender)
        return 'successfully created'


@app.route('/getMD5', methods=['GET', 'POST'])
def getMD5():
    if request.method == 'GET':
        sender = request.args['user']
        data = request.args['message']
        myMD5.make_MD5(sender, data.encode('utf-8'))
        return myMD5.get_MD5(sender)


@app.route('/sign', methods=['GET', 'POST'])
def sign():
    if request.method == 'GET':
        sender = request.args['sender']
        data = request.args['message']
        signature = myRSA.sign(data, sender)
        return signature


@app.route('/DES_encrypt_message', methods=['GET', 'POST'])
def DES_encrypt_message():
    if request.method == 'GET':
        sender = request.args['sender']
        data = request.args['message']
        DES_encrypted_message, cipher_nonce1 = myDES.encrypt(sender, data, 'message')
        return (DES_encrypted_message, cipher_nonce1)


@app.route('/DES_encrypt_signature', methods=['GET', 'POST'])
def DES_encrypt_signature():
    if request.method == 'GET':
        sender = request.args['sender']
        signature = request.args['message']
        DES_encrypted_signature, cipher_nonce2 = myDES.encrypt(sender, signature, 'signature')
        return (DES_encrypted_signature, cipher_nonce2)


@app.route('/RSA_encrypt_DESKey', methods=['GET', 'POST'])
def RSA_encrypt_DESKey():
    if request.method == 'GET':
        sender = request.args['sender']
        receiver = request.args['receiver']
        DESKey = myDES.get_key(sender)
        RSA_encrypted_DESKey = myRSA.encrypt(DESKey, receiver, sender)
        return RSA_encrypted_DESKey


def store(content, path):
    with open(path, 'wb') as fp:
        fp.write(content)


@app.route('/sendAll', methods=['GET', 'POST'])
def sendAll():
    if request.method == 'POST':
        sender = request.json['sender']
        receiver = request.json['receiver']
        DES_encrypted_message = request.json['DES_encrypted_message'].encode('utf-8')
        DES_encrypted_signature = request.json['DES_encrypted_signature'].encode('utf-8')
        RSA_encrypted_DESKey = request.json['RSA_encrypted_DESKey'].encode('utf-8')
        nonce1 = request.json['nonce1'].encode('utf-8')
        nonce2 = request.json['nonce2'].encode('utf-8')

        receiver_path = os.path.join(os.path.dirname(__file__), 'USER-'+receiver)

        DES_encrypted_message_path = os.path.join(receiver_path, receiver + '-' + 'message' + '-' + 'DESciphertext.txt')
        DES_encrypted_signature_path = os.path.join(receiver_path, receiver + '-' + 'signature' + '-' + 'DESciphertext.txt')
        RSA_encrypted_DESKey_path = os.path.join(receiver_path, receiver+'-'+'RSAciphertext.txt')
        nonce1_path = os.path.join(receiver_path, receiver + '-' + 'message' + '-' + 'DESnonce.txt')
        nonce2_path = os.path.join(receiver_path, receiver + '-' + 'signature' + '-' + 'DESnonce.txt')
        store(DES_encrypted_message, DES_encrypted_message_path)
        store(DES_encrypted_signature, DES_encrypted_signature_path)
        store(RSA_encrypted_DESKey, RSA_encrypted_DESKey_path)
        store(nonce1, nonce1_path)
        store(nonce2, nonce2_path)

        return 'successfully sended'


@app.route('/RSA_decrypt_DESKey', methods=['GET', 'POST'])
def RSA_decrypt_DESKey():
    if request.method == 'GET':
        receiver = request.args['receiver']
        DESKey = myRSA.decrypt(receiver)
        receiver_path = os.path.join(os.path.dirname(__file__), 'USER-' + receiver)
        DESKeyPath = os.path.join(receiver_path, receiver + '-' + 'DESkey.txt')
        store(base64.b64encode(DESKey), DESKeyPath)
        return base64.b64encode(DESKey)


@app.route('/DES_decrypt_message', methods=['GET', 'POST'])
def DES_decrypt_message():
    if request.method == 'POST':
        receiver = request.json['receiver']
        tp = request.json['tp']
        message = myDES.decrypt(receiver, tp)
        return message


@app.route('/DES_decrypt_signature', methods=['GET', 'POST'])
def DES_decrypt_signature():
    if request.method == 'POST':
        receiver = request.json['receiver']
        tp = request.json['tp']
        signature = myDES.decrypt(receiver, tp)
        return signature


@app.route('/check_sign', methods=['GET', 'POST'])
def check_sign():
    if request.method == 'POST':
        sender = request.json['sender']
        message = request.json['message']
        signature = request.json['signature'].encode('utf-8')
        result = myRSA.check_sign(message, signature, sender)
        return result


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9990)