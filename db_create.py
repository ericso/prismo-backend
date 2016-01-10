from server.application import db, create_app
from config import BaseConfig


db.create_all(app=create_app(BaseConfig))
