from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import config
from user import User
import encryption
import base64
import requests

app = Flask(__name__)

# Secret key for encryption and HMAC (16 bytes for AES-128)

app.config['SECRET_KEY'] = config.SECRET_KEY

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

messages = []
users = {
    "admin": "admin",
    "minda": "minda1",
    "ledy": "ledy1",
    "naya": "naya1"
}

@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username, users[username])
    return None

# Route for serving HTML templates and handling form submissions
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            user = User(username, password)
            login_user(user)
            return redirect(url_for('chat'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@app.route('/send_message', methods=['POST'])
def send_message():
    """
    Function render FE chat.html
    NOTE: Need a separate handler for testing
    :return:
    """
    user = request.form.get('user')
    message = request.form.get('message')

    encrypted_message = encryption.EncryptionHelper.aes_encrypt(message.encode())

    hmac_signature = encryption.EncryptionHelper.generate_hmac(encrypted_message)
    test_message = {'user': user,
                     'message': base64.b64encode(encrypted_message).decode(),
                     'hmac_signature': hmac_signature}
    messages.append({'user': user,
                     'message': base64.b64encode(encrypted_message).decode(),
                     'hmac_signature': hmac_signature})
    response = requests.post("http://127.0.0.1:8000/send_message", json=test_message)
    print(response.content)
    return render_template('chat.html')


@app.route('/receive_messages', methods=['GET'])
def receive_messages():
    """
    Function to receive decrypted message from server
    :return:
    """
    decrypted_messages = []
    for msg in messages:
        if encryption.EncryptionHelper.verify_hmac(ciphertext=base64.b64decode(msg['message']), received_hmac=msg['hmac_signature']):
            decrypted_message = encryption.EncryptionHelper.aes_decrypt(base64.b64decode(msg['message']))
            decrypted_messages.append({'user': msg['user'], 'message': decrypted_message.decode()})
        else:
            decrypted_messages.append({'user': msg['user'], 'message': 'Message tampered!'})
    return jsonify(decrypted_messages)


if __name__ == '__main__':
    app.run(debug=True)
