import datetime
from datetime import date

from passlib.apps import custom_app_context as pwd_context
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired

from flask import current_app
from sqlalchemy.sql.expression import ClauseElement

from server.application import db


class User(db.Model):
  __tablename__ = 'users'

  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(32), index=True)
  password_hash = db.Column(db.String(128))
  admin = db.Column(db.Boolean(), default=False)
  created_at = db.Column(db.DateTime, server_default=db.func.now())
  updated_at = db.Column(
      db.DateTime, server_default=db.func.now(), onupdate=db.func.now())


  def hash_password(self, password):
    """Hashes user-given password before storing in database
    """
    # Use the sha256_crypt hashing algorithm from PassLib
    self.password_hash = pwd_context.encrypt(password)

  def verify_password(self, password):
    """Verifies a user-given password against hashed password from database
    """
    return pwd_context.verify(password, self.password_hash)

  def generate_auth_token(self, expiration=600):
    """Creates an authorization token
    """
    s = Serializer(
      current_app.config['SECRET_KEY'],
      expires_in=expiration
    )
    return s.dumps({'id': self.id})

  @staticmethod
  def verify_auth_token(token):
    """Verify the token and return the user object if verifies
    """
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
      data = s.loads(token)
    except SignatureExpired:
      return None # valid token but expired
    except BadSignature:
      return None # invalid token
    user = User.query.get(data['id'])
    return user


def get_or_create(model, defaults=None, **kwargs):
  """
  Convenience method for getting a record if it exists, otherwise creating it.

  Args:
    model: {db.Model} The model to get or create a record from.
    defaults: {dict} Dictionary of default key, value pairs.

  Returns:
    instance, False if record exists
    instance, True if not
  """
  instance = model.query.filter_by(**kwargs).first()
  if instance:
    return instance, False
  else:
    params = dict((k, v) for k, v in kwargs.iteritems() if not isinstance(v, ClauseElement))
    params.update(defaults or {})
    instance = model(**params)
    db.session.add(instance)
    return instance, True
