import os

class Config(object):
    # Configuration par rapport à une clé secrète.
    SECRET_KEY = os.environ.get('SECRET_KEY') or "secret_string"

    # Configuration par rapport à MySQL pour SQLAlchemy.
    # SQLALCHEMY_DATABASE_URI = 'mysql://root:@localhost/MSPR'
    # SQLALCHEMY_TRACK_MODIFICATIONS = False
