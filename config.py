import os
from dotenv import load_dotenv


load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = os.getenv('MAIL_PORT')
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS')
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')

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

