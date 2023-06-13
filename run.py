import os
from app import create_app
from OpenSSL import SSL

if __name__ == '__main__':

    app = create_app()
    
    cert = os.getenv('CERT_KEY_PATH')
    key = os.getenv('PRIVATE_KEY_PATH')
    app.run(ssl_context=(cert, key))
