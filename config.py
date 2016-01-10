"""Configuration file"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class BaseConfig(object):
  """Base configuration object."""

  # flask core settings
  SECRET_KEY = "secret"
  PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 30

  # Enable protection agains *Cross-site Request Forgery (CSRF)*
  CSRF_ENABLED = True
  CSRF_SESSION_KEY = 'secret'

  # flask SQLAlchemy settings
  SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')

  # Heroku Postgresql
  # SQLALCHEMY_DATABASE_URI = (
  # 	'postgres://tiknhdbuifwvtr:-N7XTfYmu9NZt6CipFZY5QHVQD@ec2-54-225-197-30' + '.compute-1.amazonaws.com:5432/ddvjepnusqct8l')

  DATABASE_CONNECT_OPTIONS = {}

  # Application threads. A common general assumption is
  # using 2 per available processor cores - to handle
  # incoming requests using one and performing background
  # operations using the other.
  THREADS_PER_PAGE = 2

  # SERVER_NAME = 'spinq.co:5000'


class TestConfig(BaseConfig):
  """Testing configuration object."""

  CSRF_ENABLED = False

  PRESERVE_CONTEXT_ON_EXCEPTION = False

  SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'testing.db')
