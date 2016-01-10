import basicauth


def add_cors_headers(response):
  """Adds CORS headers to the response for cross-domain requests.
  """
  response.headers.add('Access-Control-Allow-Origin', '*')
  response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
  return response


def decode_basic_auth_info(request):
  """Returns a tuple of the username, password from basic auth header.
  """
  auth_string = request.headers['Authorization']
  auth_username, auth_password = basicauth.decode(auth_string)
  return (auth_username, auth_password)
