import os
from flask import Flask
from flask_login import LoginManager
from dotenv import load_dotenv
from src.config import Config

from src.auth.routes import auth_bp
from src.messages.routes import messages_bp

from src.extensions import db, login_manager, csrf, migrate
load_dotenv()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    login_manager.init_app(app)
    csrf.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)

    from src import models

    app.register_blueprint(auth_bp)
    app.register_blueprint(messages_bp)


    return app