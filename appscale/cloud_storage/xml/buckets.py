from boto.exception import S3ResponseError
from boto.s3.bucket import Bucket
from boto.s3.connection import S3Connection
from flask import current_app, request, Response
from typing import Tuple, Union

from .decorators import authenticate_xml
from ..buckets import index_bucket
from ..constants import HTTP_CONFLICT
from ..constants import HTTP_NOT_FOUND
from ..constants import HTTP_NO_CONTENT
from ..utils import xml_error


@authenticate_xml
def create_bucket(conn: S3Connection, bucket_name: str, **kwargs) -> Union[str, Response]:
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

    project: str = request.headers['x-goog-project-id']
    index_bucket(bucket_name, project)

    conn.create_bucket(bucket_name)

    return ''


@authenticate_xml
def delete_bucket(conn: S3Connection, bucket_name: str, **kwargs) -> Union[Tuple[str, int], Response]:
    """ Deletes an empty bucket.

    Args:
        bucket_name: A string specifying a bucket name.
        conn: An S3Connection instance.
    """
    current_app.logger.debug('headers: {}'.format(request.headers))
    try:
        bucket: Bucket = conn.get_bucket(bucket_name)
    except S3ResponseError:
        return xml_error('NoSuchBucket', 'The specified bucket does not exist.', http_code=HTTP_NOT_FOUND)

    try:
        bucket.delete()
    except S3ResponseError:
        return xml_error('BucketNotEmpty', 'The bucket you tried to delete is not empty.', http_code=HTTP_CONFLICT)

    return '', HTTP_NO_CONTENT
