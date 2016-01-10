from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.restful import Api
from flask.ext.cors import CORS


db = SQLAlchemy()

def create_app(config, debug=False, testing=False, config_overrides=None):
  """Application factory
  """
  # define the WSGI application object
  flask_app = Flask(__name__)

  # configuration
  flask_app.config.from_object(config)
  flask_app.debug = debug
  flask_app.testing = testing

  if config_overrides:
    flask_app.config.update(config_overrides)

  # initialize the database
  db.init_app(flask_app)

  # blueprints
  from app.users import users_blueprint
  flask_app.register_blueprint(users_blueprint)

  # flask-restful
  from app.users import UserListAPI, UserAPI

  api = Api(prefix='/api/v0')
  api.add_resource(UserListAPI, '/users', endpoint='users')
  api.add_resource(UserAPI, '/users/<id>', endpoint='user')

  api.init_app(flask_app)

  cors = CORS(resources={r'/api/*': {'origins': '*'}})
  cors.init_app(flask_app)

  return flask_app
