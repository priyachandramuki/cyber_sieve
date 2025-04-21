import os
from flask import Flask, render_template, request, send_file, redirect, url_for
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import zipfile

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def hybrid_encrypt(secret_message, public_key_data):
    # Load public key
    recipient_key = RSA.import_key(public_key_data)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)

    # Generate AES key and encrypt secret
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(secret_message.encode())

    encrypted_key = cipher_rsa.encrypt(aes_key)

    return {
        'encrypted_key': base64.b64encode(encrypted_key).decode(),
        'nonce': base64.b64encode(cipher_aes.nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }

def hybrid_decrypt(keyinfo, private_key_data):
    encrypted_key = base64.b64decode(keyinfo['encrypted_key'])
    nonce = base64.b64decode(keyinfo['nonce'])
    tag = base64.b64decode(keyinfo['tag'])
    ciphertext = base64.b64decode(keyinfo['ciphertext'])

    private_key = RSA.import_key(private_key_data)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    secret_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return secret_message.decode()

@app.route('/')
def chaff():
    return render_template('chaff.html')

@app.route('/winnow')
def do_winnow():
    return render_template('winnow.html')

@app.route('/chaff', methods=['POST'])
def handle_chaff():
    secret_message = request.form['secret_message']
    public_key = request.files['public_key']
    uploaded_file = request.files['file']
    filename = uploaded_file.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    uploaded_file.save(file_path)

    keyinfo = hybrid_encrypt(secret_message, public_key.read())

    keyinfo_path = os.path.join(app.config['UPLOAD_FOLDER'], 'keyinfo.txt')
    with open(keyinfo_path, 'w') as f:
        for k, v in keyinfo.items():
            f.write(f"{k}:{v}\n")

    return send_file(keyinfo_path, as_attachment=True)

@app.route('/winnow', methods=['POST'])
def handle_winnow():
    chaffed_file = request.files['file']
    keyinfo_file = request.files['keyinfo']
    private_key = request.files['private_key']

    keyinfo_data = {}
    for line in keyinfo_file.read().decode().splitlines():
        k, v = line.split(":", 1)
        keyinfo_data[k] = v

    decrypted = hybrid_decrypt(keyinfo_data, private_key.read())

    return render_template('winnow.html', decrypted=decrypted)

if __name__ == '__main__':
    app.run(debug=True)
