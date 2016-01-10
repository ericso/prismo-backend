import json
from base64 import b64encode
from datetime import date, datetime

from server.application import db, create_app
from server.app.models import User
from server.common.tests import BaseTestCase


class ModelsTest(BaseTestCase):
  """Test case for models."""

  def setUp(self):
    with self.app.app_context():
      db.create_all()

  def tearDown(self):
    with self.app.app_context():
      db.session.remove()
      db.drop_all()

  ### Tests ###
  def test_created_user_is_not_admin(self):
    user = User(username='username')
    user.hash_password('password')
    db.session.add(user)
    db.session.commit()
    self.assertFalse(user.admin)
