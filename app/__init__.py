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
    log_dir = app.config.get('LOG_DIR', 'logs')
        
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Create the file upload directory if it doesn't exist
    upload_dir = app.config.get('UPLOAD_FOLDER', 'uploads')
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)

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
        return render_template('error.html',error_code=404), 404


    @app.errorhandler(401)
    def not_found_error(error):
        return render_template('error.html',error_code=401), 401


    @app.errorhandler(403)
    def not_found_error(error):
        return render_template('error.html',error_code=403), 403

    @app.errorhandler(500)
    def not_found_error(error):
        return render_template('error.html',error_code=500), 500



    @app.before_request
    def before_request():
        if current_user.is_authenticated:
            pass
            # current_user.update_last_activity()

    ### Add Security Headers
    # This is for preventing clickjacking attacks
    @app.after_request
    def add_security_headers(r):
        r.headers['X-Frame-Options'] = 'SAMEORIGIN'
        return r
    
    return app
