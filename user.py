from flask_login import UserMixin
import bcrypt

class User(UserMixin):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def verify_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
