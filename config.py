import os
from dotenv import load_dotenv


load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER='sandbox.smtp.mailtrap.io'
    MAIL_PORT=2525
    MAIL_USERNAME='05c58ad55dd8ff'
    MAIL_DEFAULT_SENDER='05c58ad55dd8ff@mailtrap.io'
    MAIL_PASSWORD='c23e86ce4d5509'
    MAIL_USE_TLS=True
    MAIL_USE_SSL=False

    # Limiter Configuration
    RATELIMIT_DEFAULT = "100 per day"
    RATELIMIT_HEADERS_ENABLED = True

    # reCAPTCHA configuration
    RECAPTCHA_SITE_KEY = 'your-recaptcha-site-key'
    RECAPTCHA_SECRET_KEY = 'your-recaptcha-secret-key'

    LOG_DIR = os.getenv('LOG_DIR')
    LOG_LEVEL = os.getenv('LOG_LEVEL')
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')
class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

# Set the appropriate configuration class based on the environment
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig
}

