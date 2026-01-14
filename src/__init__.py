import os
from flask import Flask
from flask_login import LoginManager
from dotenv import load_dotenv

load_dotenv()

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY'),
        PASSWORD_PEPPER=os.environ.get('PASSWORD_PEPPER'),
        DATABASE='sqlite3.db',
    )

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models.user import User
    from .db import get_db
    @login_manager.user_loader
    def load_user(user_id):
        db = get_db()
        user_row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user_row:
            return User(user_id=user_row['id'], username=user_row['username'])
        return None

    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)

    from . import messages
    app.register_blueprint(messages.bp)

    return app