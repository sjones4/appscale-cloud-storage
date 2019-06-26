from boto.exception import S3ResponseError
from flask import current_app
from flask import request

from .decorators import authenticate_xml
from ..buckets import index_bucket
from ..constants import HTTP_CONFLICT
from ..constants import HTTP_NOT_FOUND
from ..constants import HTTP_NO_CONTENT
from ..utils import xml_error


@authenticate_xml
def create_bucket(conn, bucket_name, **kwargs):
    """ Creates a new bucket.

    Args:
        bucket_name: A string specifying a bucket name.
        conn: An S3Connection instance.
    Returns:
        An empty or error response
    """
    current_app.logger.debug('headers: {}'.format(request.headers))

    # TODO: Do the following lookup and create under a lock.
    if conn.lookup(bucket_name) is not None:
        return xml_error('BucketAlreadyExists', 'The requested bucket name is not available.', http_code=HTTP_CONFLICT)

    project = request.headers['x-goog-project-id']
    index_bucket(bucket_name, project)

    conn.create_bucket(bucket_name)

    return ''


@authenticate_xml
def delete_bucket(conn, bucket_name, **kwargs):
    """ Deletes an empty bucket.

    Args:
        bucket_name: A string specifying a bucket name.
        conn: An S3Connection instance.
    """
    current_app.logger.debug('headers: {}'.format(request.headers))
    try:
        bucket = conn.get_bucket(bucket_name)
    except S3ResponseError:
        return xml_error('NoSuchBucket', 'The specified bucket does not exist.', http_code=HTTP_NOT_FOUND)

    try:
        bucket.delete()
    except S3ResponseError:
        return xml_error('BucketNotEmpty', 'The bucket you tried to delete is not empty.', http_code=HTTP_CONFLICT)

    return '', HTTP_NO_CONTENT
