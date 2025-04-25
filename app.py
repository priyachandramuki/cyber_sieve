import os
import io
import json
import base64
import zipfile
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.IO.PEM import decode as pem_decode

app = Flask(__name__)
app.secret_key = 'cybersieve-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    rsa_pub = db.Column(db.Text, nullable=True)
    rsa_priv = db.Column(db.Text, nullable=True)
    key_expiration = db.Column(db.DateTime, nullable=True)
    created = db.Column(db.DateTime, default=datetime.utcnow)

# PEM format validation
def is_valid_pem(key_data):
    try:
        key_data_str = key_data.decode('utf-8')
        pem_decode(key_data_str)
        return True
    except (ValueError, UnicodeDecodeError):
        return False

# Initialize database
def initialize_database():
    with app.app_context():
        db.drop_all()
        db.create_all()

# Routes

@app.route('/')
def index():
    # If logged in, show home dashboard. Else, send to login.
    return redirect(url_for('home')) if 'user_id' in session else redirect(url_for('login'))

@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()

        flash("Registered successfully. Please login.")
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uid = request.form['username']
        password = request.form['password']
        user = User.query.filter((User.username == uid) | (User.email == uid)).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('chaff'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    key = RSA.generate(2048)
    pub_key = key.publickey().export_key()
    priv_key = key.export_key()

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        zip_file.writestr("public.pem", pub_key.decode())
        zip_file.writestr("private.pem", priv_key.decode())
    zip_buffer.seek(0)

    user = User.query.get(session['user_id'])
    user.rsa_pub = pub_key.decode()
    user.rsa_priv = priv_key.decode()
    user.key_expiration = datetime.utcnow() + timedelta(days=30)
    db.session.commit()

    return send_file(zip_buffer, as_attachment=True, download_name="rsa_keys.zip", mimetype='application/zip')

@app.route('/revoke_keys', methods=['POST'])
def revoke_keys():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    user.rsa_pub = None
    user.rsa_priv = None
    user.key_expiration = None
    db.session.commit()
    flash("Your RSA keys have been revoked.")
    return redirect(url_for('generate_keys'))

@app.route('/chaff', methods=['GET', 'POST'])
def chaff():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found.")
        return redirect(url_for('login'))

    if user.key_expiration and user.key_expiration < datetime.utcnow():
        flash("RSA keys expired. Generate new keys.")
        return redirect(url_for('generate_keys'))

    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        secret_message = request.form.get('secret_message', '')
        public_key_file = request.files.get('public_key')

        if not uploaded_file or not public_key_file or not secret_message:
            flash("Please provide all required inputs.")
            return redirect(url_for('chaff'))

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
        uploaded_file.save(file_path)

        public_key_data = public_key_file.read()
        if not is_valid_pem(public_key_data):
            flash("Invalid public key format.")
            return redirect(url_for('chaff'))

        public_key = RSA.import_key(public_key_data)
        cipher_rsa = PKCS1_OAEP.new(public_key)

        aes_key = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(secret_message.encode())

        encrypted_key = cipher_rsa.encrypt(aes_key)

        keyinfo = {
            'encrypted_key': base64.b64encode(encrypted_key).decode(),
            'nonce': base64.b64encode(cipher_aes.nonce).decode(),
            'tag': base64.b64encode(tag).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode()
        }

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            zip_file.write(file_path, arcname=uploaded_file.filename)
            zip_file.writestr('keyinfo.json', json.dumps(keyinfo))

        zip_buffer.seek(0)
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name=f"chaffed_{uploaded_file.filename.split('.')[0]}.zip",
            mimetype='application/zip'
        )

    return render_template('chaff.html')

@app.route('/winnow', methods=['GET', 'POST'])
def winnow():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found.")
        return redirect(url_for('login'))

    if user.key_expiration and user.key_expiration < datetime.utcnow():
        flash("RSA keys expired.")
        return redirect(url_for('generate_keys'))

    result = None
    if request.method == 'POST':
        chaffed_file = request.files.get('chaffed_file')
        keyinfo_file = request.files.get('keyinfo')
        private_key_file = request.files.get('private_key')

        if not keyinfo_file or not private_key_file:
            flash("Keyinfo and private key required.")
            return redirect(url_for('winnow'))

        private_key_data = private_key_file.read()
        if not is_valid_pem(private_key_data):
            flash("Invalid private key format.")
            return redirect(url_for('winnow'))

        try:
            private_key = RSA.import_key(private_key_data)
            cipher_rsa = PKCS1_OAEP.new(private_key)

            keyinfo = json.loads(keyinfo_file.read().decode('utf-8'))
            encrypted_key = base64.b64decode(keyinfo['encrypted_key'])
            nonce = base64.b64decode(keyinfo['nonce'])
            tag = base64.b64decode(keyinfo['tag'])
            ciphertext = base64.b64decode(keyinfo['ciphertext'])

            aes_key = cipher_rsa.decrypt(encrypted_key)

            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
            secret = cipher_aes.decrypt_and_verify(ciphertext, tag)
            result = secret.decode()
        except Exception as e:
            result = f"Error: {str(e)}"

    return render_template('winnow.html', result=result)

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
