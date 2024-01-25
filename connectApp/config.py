import os


basedir = os.path.abspath(os.path.dirname(__file__))

# Assets Management
ASSETS_ROOT = os.getenv('ASSETS_ROOT', '/connectApp/static/css') 