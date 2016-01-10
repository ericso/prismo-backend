#!/usr/bin/env python
# -*- coding: utf-8 -*-
from server.application import create_app

from config import BaseConfig


app = create_app(BaseConfig)

# This is only used when running locally. When running live, gunicorn runs
# the application.
if __name__ == '__main__':
  app.run(host='127.0.0.1', port=5000, debug=True)
