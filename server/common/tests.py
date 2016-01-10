from flask import Flask
from unittest import TestCase

from datetime import date
from base64 import b64encode

from server.application import db, create_app
from server.app.models import User
from server.common.util import rand_string_gen, rand_date
from config import TestConfig


class BaseTestCase(TestCase):

  def create_app(self):
    return create_app(TestConfig, debug=True, testing=True)

  def __call__(self, result=None):
    self._pre_setup()
    super(BaseTestCase, self).__call__(result)
    self._post_teardown()

  def _pre_setup(self):
    self.app = self.create_app()
    self.client = self.app.test_client()
    self._ctx = self.app.test_request_context()
    self._ctx.push()

  def _post_teardown(self):
    self._ctx.pop()

  def assertRedirects(self, resp, location):
    self.assertTrue(resp.status_code in (301, 302))
    self.assertEqual(resp.location, 'http://localhost' + location)

  def assertStatus(self, resp, status_code):
    self.assertEqual(resp.status_code, status_code)

  def assertCORSHeaders(self, resp):
    self.assertIn('Access-Control-Allow-Origin', resp.headers.keys())
    self.assertIn('Access-Control-Allow-Headers', resp.headers.keys())
    self.assertIn('Access-Control-Allow-Methods', resp.headers.keys())


class UsersBaseTestCase(BaseTestCase):

  @staticmethod
  def create_user(username, password):
    """Creates a user with hashed password in the database

    :return: user object
    """
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return user

  @staticmethod
  def generate_test_users(n=1):
    """Returns a list of n test users
    """
    rv = list()
    for i in xrange(0, n):
      rv.append({'username': rand_string_gen(), 'password': rand_string_gen()})
    return rv

  @staticmethod
  def create_basic_auth_header(username, password):
    """
    :return: Basic auth header entry
    """
    return {
      'Authorization': 'Basic %s' % b64encode("{0}:{1}".format(username, password))
    }


class CatsBaseTestCase(BaseTestCase):

  @staticmethod
  def create_cat(name, birthdate, owner=None):
    """Creates a cat

    :return: cat object
    """
    cat = Cat(name=name, birthdate=birthdate, owner=owner)
    db.session.add(cat)
    db.session.commit()
    return cat

  @staticmethod
  def generate_test_cats(n=1):
    """Returns a list of n test cats
    """
    rv = list()
    # seed dates
    seed_start = date(year=1970, month=1, day=1)
    seed_end = date(year=1971, month=1, day=1)
    for i in xrange(0, n):
      birthdate = rand_date(seed_start, seed_end)
      rv.append({
        'name': rand_string_gen(),
        'birthdate': birthdate
      })
    return rv

class AttributesBaseTestCase(BaseTestCase):

  @staticmethod
  def create_attribute(name, value):
    """Creates an attribute for a cat

    :return: attribute object
    """
    attribute = Attribute(name=name, value=value)
    db.session.add(attribute)
    db.session.commit()
    return attribute
