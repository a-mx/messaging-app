from flask_login import UserMixin
class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username
if __name__ == "__main__":
    pass