# import os
# from api.constants import SECURITY_PATH
# basedir = os.path.abspath(os.path.dirname(SECURITY_PATH))
#
# class Config(object):
#     # ...
#     SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'RBAC.db')
#     SQLALCHEMY_TRACK_MODIFICATIONS = True

import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    # ...
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False