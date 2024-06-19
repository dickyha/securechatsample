from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import config
from user import User
import encryption
import base64
import requests
import handler
app = Flask(__name__)

# Secret key for encryption and HMAC (16 bytes for AES-128)

app.config['SECRET_KEY'] = config.SECRET_KEY

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

messages = []
users = {
    "admin": "$2b$12$X3Z9zq3wba9myBJU4veEbeGPObm0PAGvJLdcyWRs3HsnGJgMLxsfK",
    "minda": "$2b$12$2OjrVGOWwqs75ZLoMI912e3Yuy9eOjHc.IWVGdgInyfN4zX7EdH/W",
    "ledy": "$2b$12$q677g8A5l7MAORkVFZ2D2OHESsvOyRNvyaVAm6UVnyDT5Ydg89a8O",
    "naya": "$2b$12$O/36/A7WbSG6SM7wZ980aOBbVAtbr9/h6cy31hodbaEPm.rSNvLpG"
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
        if username in users:
            user = User(username, users[username])
            if user.verify_password(password):
                login_user(user)
                return redirect(url_for('chat'))
            else:
                flash('Invalid username or password')
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
    # user = request.form.get('user')
    user = current_user.username
    message = request.form.get('message')
    enc_message = handler.ChatHandler.process_message(user=user, message=message)
    response = requests.post(f"http://{config.SERVER_ADDR}:{config.SERVER_PORT}/send_message", json=enc_message).json()
    if response['status'] == 200:
        return render_template('chat.html')
    else:
        return render_template('chat.html')


@app.route('/receive_messages', methods=['GET'])
def receive_messages():
    """
    Function to receive decrypted message from server
    :return:
    """
    decrypted_messages = []
    response = requests.get(f"http://{config.SERVER_ADDR}:{config.SERVER_PORT}/get_messages").json()
    handler.ChatHandler.receive_message(response['data'])
    if len(response.get('data')) == 0:
        return jsonify(decrypted_messages)

    for msg in response.get('data'):
        if encryption.EncryptionHelper.verify_hmac(ciphertext=base64.b64decode(msg['message']), received_hmac=msg['hmac_signature']):
            decrypted_message = encryption.EncryptionHelper.aes_decrypt(base64.b64decode(msg['message']))
            decrypted_messages.append({'user': msg['user'], 'message': decrypted_message.decode()})
        else:
            decrypted_messages.append({'user': msg['user'], 'message': 'Message tampered!'})
    return jsonify(decrypted_messages)


if __name__ == '__main__':
    app.run(debug=True, host=config.APP_ADDR, port=config.APP_PORT)
