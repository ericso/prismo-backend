import json

from server.application import db
from server.app.models import User
from server.app.serializers import convert_date_to_string
from server.common.tests import UsersBaseTestCase


class UsersTestCase(UsersBaseTestCase):
  """Test case for users."""

  def setUp(self):
    with self.app.app_context():
      db.create_all()

  def tearDown(self):
    with self.app.app_context():
      db.session.remove()
      db.drop_all()

  def get_token_for_user(self, username, password, failure=False):
    """Shortcut method for creating a user in the test db
    and requesting an auth token via the API
    """
    test_user = UsersBaseTestCase.create_user(
      username=username,
      password=password
    )

    if failure:
      headers = UsersBaseTestCase.create_basic_auth_header(
        username=username,
        password='thisisincorrectpassword'
      )
    else:
      headers = UsersBaseTestCase.create_basic_auth_header(
        username=username,
        password=password
      )

    response = self.client.get(
      '/api/v0/token',
      headers=headers
    )
    return response

  def authorize_user(self, username, password, failure=False):
    """Shortcut method for creating a user in the test db
    and authenticating the user via the API
    """
    test_user = UsersBaseTestCase.create_user(
      username=username,
      password=password
    )

    headers = dict()
    headers['Content-Type'] = 'application/json'

    if failure:
      data = dict(username=username, password='thisisincorrectpassword')
    else:
      data = dict(username=username, password=password)

    json_data = json.dumps(data)
    json_data_length = len(json_data)
    headers['Content-Length'] =  json_data_length

    response = self.client.post(
      '/api/v0/authenticate',
      headers=headers,
      data=json_data
    )
    return response

  ### Tests ###
  def test_get_all_users(self):
    num_users = 5
    users = UsersBaseTestCase.generate_test_users(num_users)
    for user in users:
      UsersBaseTestCase.create_user(user['username'], user['password'])

    auth_headers = UsersBaseTestCase.create_basic_auth_header(
      username=users[0]['username'],
      password=users[0]['password']
    )
    response = self.client.get(
      '/api/v0/users',
      headers=auth_headers
    )
    self.assertStatus(response, 200)
    data = json.loads(response.data)
    users = data['data']
    self.assertEqual(len(users), num_users)

  def test_get_user_by_id(self):
    # create user
    test_username = 'test_user'
    test_password = 'test_password'
    test_user = UsersBaseTestCase.create_user(
      username=test_username,
      password=test_password
    )

    auth_headers = UsersBaseTestCase.create_basic_auth_header(
      username=test_username,
      password=test_password
    )
    response = self.client.get(
      '/api/v0/users/%s' % (test_user.id,),
      headers=auth_headers
    )
    self.assertEqual(response.status_code, 200)
    user = json.loads(response.data)
    self.assertEqual(user['username'], test_username)

  def test_get_user_not_found(self):
    # create user
    test_username = 'test_user'
    test_password = 'test_password'
    test_user = UsersBaseTestCase.create_user(
      username=test_username,
      password=test_password
    )
    # create the auth header
    auth_headers = UsersBaseTestCase.create_basic_auth_header(
      username=test_username,
      password=test_password
    )
    response = self.client.get(
      '/api/v0/users/999', # this user doesn't exist
      headers=auth_headers
    )
    self.assertEqual(response.status_code, 404)

  def test_get_user_by_username(self):
    # create user
    test_username = 'test_user'
    test_password = 'test_password'
    test_user = UsersBaseTestCase.create_user(
      username=test_username,
      password=test_password
    )

    auth_headers = UsersBaseTestCase.create_basic_auth_header(
      username=test_username,
      password=test_password
    )
    response = self.client.get(
      '/api/v0/users/%s' % (test_username,),
      headers=auth_headers
    )
    self.assertStatus(response, 200)
    user = json.loads(response.data)
    self.assertEqual(user['username'], test_username)

  def test_create_new_user_but_missing_arguments(self):
    response = self.client.post(
      '/api/v0/users',
      content_type='application/json'
    )
    self.assertEqual(response.status_code, 400)

  def test_create_new_user_but_invalid_request_type(self):
    response = self.client.post(
      '/api/v0/users',
      content_type='text/html'
    )
    self.assertEqual(response.status_code, 400)

  def test_create_new_user_successfully(self):
    headers = {
      'Content-Type': 'application/json'
    }
    data = dict(username='test_user', password='test_password')
    json_data = json.dumps(data)
    json_data_length = len(json_data)
    headers['Content-Length'] =  json_data_length

    response = self.client.post(
      '/api/v0/users',
      headers=headers,
      data=json_data
    )
    self.assertEqual(response.status_code, 201)
    res_data = json.loads(response.data)
    self.assertEqual(res_data['user']['username'], data['username'])
    self.assertIn('uri', res_data['user'].keys())

  def test_create_new_user_but_user_exists(self):
    # create user
    test_username = 'test_user'
    test_password = 'test_password'
    test_user = UsersBaseTestCase.create_user(
      username=test_username,
      password=test_password
    )

    # try to create the same user by sending request
    headers = {
      'Content-Type': 'application/json'
    }
    data = dict(username=test_username, password=test_password)
    json_data = json.dumps(data)
    json_data_length = len(json_data)
    headers['Content-Length'] = json_data_length

    response = self.client.post(
      '/api/v0/users',
      headers=headers,
      data=json_data
    )
    self.assertEqual(response.status_code, 403)

  def test_update_user_password(self):
    """
    A user should be able to change their own password
    """
    # create user
    test_username = 'test_user'
    test_password = 'test_password'
    test_user = UsersBaseTestCase.create_user(
      username=test_username,
      password=test_password
    )
    headers = dict()

    # create the auth header
    headers.update(
      UsersBaseTestCase.create_basic_auth_header(
        username=test_username,
        password=test_password
      )
    )

    # create the json payload
    new_password = 'new_password'
    data = dict(password=new_password)
    json_data = json.dumps(data)
    json_data_length = len(json_data)

    # update the content headers
    headers.update({
      'Content-Type': 'application/json',
      'Content-Length': json_data_length
    })

    response = self.client.put(
      '/api/v0/users/%s' % (test_user.id,),
      headers=headers,
      data=json_data
    )
    self.assertEqual(response.status_code, 201)

  def test_update_other_users_password_fails(self):
    """
    A user should NOT be able to change another user's password
    """
    # create an authroized user
    authorized_username = 'authorized_user'
    authorized_password = 'authorized_password'
    authorized_user = UsersBaseTestCase.create_user(
      username=authorized_username,
      password=authorized_password
    )

    # create an unauthroized user
    unauthorized_username = 'unauthorized_user'
    unauthorized_password = 'unauthorized_password'
    unauthorized_user = UsersBaseTestCase.create_user(
      username=unauthorized_username,
      password=unauthorized_password
    )

    headers = dict()

    # create the un-auth header
    headers.update(
      UsersBaseTestCase.create_basic_auth_header(
        username=unauthorized_username,
        password=unauthorized_password
      )
    )

    # create the json payload
    new_password = 'new_password'
    data = dict(password=new_password)
    json_data = json.dumps(data)
    json_data_length = len(json_data)

    # update the content headers
    headers.update({
      'Content-Type': 'application/json',
      'Content-Length': json_data_length
    })

    response = self.client.put(
      '/api/v0/users/%s' % (authorized_user.id,),
      headers=headers,
      data=json_data
    )
    self.assertEqual(response.status_code, 403)

  def test_delete_user_allowed_for_admins(self):
    # create user to be deleted
    test_username = 'test_user'
    test_password = 'test_password'
    test_user = UsersBaseTestCase.create_user(
      username=test_username,
      password=test_password
    )
    test_user_id = test_user.id

    # create admin user
    admin_username = 'admin_username'
    admin_password = 'admin_password'
    admin_user = UsersBaseTestCase.create_user(
      username=admin_username,
      password=admin_password
    )
    admin_user.admin = True
    admin_user_id = admin_user.id
    headers = dict()

    # create the auth header
    headers.update(
      UsersBaseTestCase.create_basic_auth_header(
        username=admin_username,
        password=admin_password
      )
    )
    response = self.client.delete(
      '/api/v0/users/%s' % (test_user_id,),
      headers=headers
    )
    self.assertEqual(response.status_code, 202)

    # try querying for the user should return 404 NOT FOUND
    response = self.client.get(
      '/api/v0/users/%s' % (test_user_id,),
      headers=headers
    )
    self.assertEqual(response.status_code, 404)

  def test_delete_user_method_disallowed_for_non_admins(self):
    # create user
    test_username = 'test_user'
    test_password = 'test_password'
    test_user = UsersBaseTestCase.create_user(
      username=test_username,
      password=test_password
    )
    test_user_id = test_user.id

    # create non-admin user, admin flag defaults to False
    regular_username = 'regular_username'
    regular_password = 'regular_password'
    regular_user = UsersBaseTestCase.create_user(
      username=regular_username,
      password=regular_password
    )
    regular_user_id = regular_user.id
    headers = dict()

    # create the auth header
    headers.update(
      UsersBaseTestCase.create_basic_auth_header(
        username=regular_username,
        password=regular_password
      )
    )
    response = self.client.delete(
      '/api/v0/users/%s' % (test_user_id,),
      headers=headers
    )
    self.assertEqual(response.status_code, 403)

    # try querying for the user should return 200, the user is still there
    response = self.client.get(
      '/api/v0/users/%s' % (test_user_id,),
      headers=headers
    )
    self.assertEqual(response.status_code, 200)

  def test_authenticate_user_successfully(self):
    response = self.authorize_user('test_user', 'test_password')
    self.assertEqual(response.status_code, 201)

  def test_authenticate_user_unsuccessfully(self):
    response = self.authorize_user('test_user', 'test_password', failure=True)
    self.assertEqual(response.status_code, 403)
