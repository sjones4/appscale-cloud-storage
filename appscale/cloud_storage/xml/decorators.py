import functools
from boto.s3.connection import OrdinaryCallingFormat
from boto.s3.connection import S3Connection
from flask import current_app

from ..utils import s3_connection_cache


def get_connection():
    user = 'appengine_user'
    creds = current_app.config['S3_ADMIN_CREDS']
    if user not in s3_connection_cache:
        s3_connection_cache[user] = S3Connection(
            aws_access_key_id=creds['access_key'],
            aws_secret_access_key=creds['secret_key'],
            is_secure=current_app.config['S3_USE_SSL'],
            host=current_app.config['S3_HOST'],
            port=current_app.config['S3_PORT'],
            calling_format=OrdinaryCallingFormat()
        )
    return s3_connection_cache[user]


# TODO authentication...
def authenticate_xml(function):
    """ A decorator that authenticates a request and provides a connection.

    Args:
        function: Any function that requires authentication.
    """

    @functools.wraps(function)
    def decorated_function(*args, **kwargs):
        kwargs['conn'] = get_connection()

        return function(*args, **kwargs)

    return decorated_function
