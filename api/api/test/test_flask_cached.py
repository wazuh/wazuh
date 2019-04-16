import time

import connexion
from flask_caching import Cache

from api.util import flask_cached


@flask_cached
def cached_func():
    return time.process_time()


def test_cache_simple():

    app = connexion.App('simple_app')
    app.app.config['CACHE_TYPE'] = 'simple'
    app.app.config['CACHE_DEFAULT_TIMEOUT'] = 0.75    # seconds
    app.app.cache = Cache(app.app)

    with app.app.app_context():
        answer1 = cached_func()
        answer2 = cached_func()
        assert answer1 == answer2

        time.sleep(1)

        answer3 = cached_func()
        assert answer3 != answer2


def test_cache_null():

    app = connexion.App('simple_app')
    app.app.config['CACHE_TYPE'] = 'null'
    app.app.config['CACHE_DEFAULT_TIMEOUT'] = 0.75    # seconds
    app.app.cache = Cache(app.app)

    with app.app.app_context():
        answer1 = cached_func()
        answer2 = cached_func()
        assert answer1 != answer2
