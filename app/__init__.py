import os
import logging

from flask import Flask, render_template, Markup
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
# from flask_recaptcha import ReCaptcha


# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)
mail = Mail()
migrate = Migrate()
csrf = CSRFProtect()
mail = Mail()
# recaptcha = ReCaptcha()
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.config.from_object('config.Config')

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    
    # Create the log directory if it doesn't exist
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Configure the logging
    log_level = app.config.get('LOG_LEVEL', 'DEBUG')
    log_format = app.config.get('LOG_FORMAT', '[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    log_filename = os.path.join(log_dir, 'app.log')
    logging.basicConfig(level=log_level, format=log_format, filename=log_filename, filemode='a')
    

    mail.init_app(app)
    # recaptcha.init_app(app)


    # Import and register blueprints
    # from app.routes import auth, main, admin
    from app.routes import main
    # app.register_blueprint(auth)
    app.register_blueprint(main)
    # app.register_blueprint(admin)

    # Rate limiting configuration
    limiter.init_app(app)


    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.before_request
    def before_request():
        if current_user.is_authenticated:
            current_user.update_last_activity()


    return app
