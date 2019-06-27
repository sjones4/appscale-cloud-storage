import datetime
import email.utils as email_utils
import hashlib
import itertools
import json
import psycopg2
import re
import time

from boto.s3.bucket import Bucket
from boto.s3.connection import S3Connection
from boto.s3.key import Key
from boto.s3.multipart import MultiPartUpload, Part
from flask import Response
from psycopg2.extensions import connection
from typing import (cast, Any, Dict, Iterable, List, NamedTuple, Optional, Set,
                    Tuple, Union)
from xml.etree import ElementTree as ETree

from .constants import HTTP_ERROR

# A cache used to store valid access tokens.
active_tokens: Dict[str, 'Token'] = {}

# A cache used to store active S3 connections.
s3_connection_cache: Dict[str, S3Connection] = {}

# A PostgresConnector
pg_connector: 'PostgresConnector'

# This configuration is defined when the app starts.
config: Dict[str, Any]

# Types
ObjectMetadata = Dict[str, str]
Ranges = Tuple[Tuple[int, int], ...]
UploadState = Dict[str, str]


class TokenExpired(Exception):
    """ Indicates that a given authentication token has expired. """
    pass


class TokenNotFound(Exception):
    """ Indicates that a given authentication token does not exist. """
    pass


class UploadNotFound(Exception):
    """ Indicates that a given Upload ID does not exist. """
    pass


class UploadStates(object):
    """ Possible statuses for resumable uploads. """
    NEW = 'new'
    IN_PROGRESS = 'in_progress'
    COMPLETE = 'complete'


class Token(NamedTuple):
    user: str
    expiration: datetime.datetime


class PostgresConnector(object):
    """ Connection helper for postgresql"""
    def __init__(self, *args, **kwargs) -> None:
        self._args = args
        self._kwargs = kwargs
        self._connection: connection = None

    def connect(self) -> connection:
        self._connection = psycopg2.connect(*self._args, **self._kwargs)
        return self._connection

    def close(self) -> None:
        self._connection.close()


def camel_to_snake(name: str) -> str:
    """ Converts a string from camelCase to snake_case.

    Args:
        name: A string in camelCase.
    Returns:
        A string in snake_case.
    """
    return re.sub('([a-z])([A-Z])', r'\1_\2', name).lower()


def url_strip_host(url: str) -> str:
    """ Removes the scheme, host and port from http[s] urls.

    For example:
      https://host:80/path/goes/here -> path/goes/here

    Args:
        url: A relative or absolute url
    Returns:
        The url with any host prefix removed.
    """
    return (url[url.find('/', 8)+1:]
            if url.startswith('http://') or url.startswith('https://')
            else url)


def error(message: str, code: int=HTTP_ERROR) -> Response:
    """ A convenience function for error responses.

    Args:
        message: A string containing the error message.
        code: An integer containing an HTTP status code.
    Returns:
        A response with a JSON body specifying the error.
    """
    response = json.dumps({'error': {'message': message, 'code': code}})
    return Response(response, mimetype='application/json', status=code)


def xml_error(code: str, message: str,
              details: Optional[Union[str, Dict[str, str]]]='',
              http_code: int=HTTP_ERROR) -> Response:
    """ A convenience function for formatting XML error messages.

    Args:
        code: A string describing the error code.
        message: A string containing the error message.
        details: Additional details about the error.
        http_code: An integer containing an HTTP status code.
    Returns:
        A Flask response specifying the error.
    """
    error_info: Dict[str, Any] = {'Code': code, 'Message': message}
    if details:
        error_info['Details'] = details
    return Response(object_as_xml(error_info, 'Error'), mimetype='application/xml', status=http_code)


def object_as_xml(object_dict: Dict[str, Any], element: str, namespace: Optional[str]=None) -> str:
    """ Utility function for converting a dict to an xml string.

    Args:
        object_dict: The dict to be converted to xml.
        element: The name of the xml document element.
        namespace: Optional default namespace for the document.
    Returns:
        A textual representation of the object as xml.
    """
    om = ETree.Element(element)
    if namespace:
        om.set('xmlns', namespace)
    _object_as_om(om, object_dict)
    return ETree.tostring(om, encoding='utf8')


def _object_as_om(om: ETree.Element, object_dict: Dict[str, Any]) -> None:
    """ Internals for object to model conversion"""
    for key, value in object_dict.items():
        if isinstance(value, dict):
            sub_element = ETree.SubElement(om, key)
            _object_as_om(sub_element, value)
        elif isinstance(value, list):
            for sub_value in value:
                sub_element = ETree.SubElement(om, key)
                if isinstance(sub_value, dict):
                    _object_as_om(sub_element, sub_value)
                else:
                    sub_element.text = str(sub_value)
        else:
            sub_element = ETree.SubElement(om, key)
            sub_element.text = str(value)


def index_bucket(bucket_name: str, project: str) -> None:
    """ Associates a bucket with a project.

    Args:
        bucket_name: A string containing the bucket name.
        project: A string containing the project ID.
    """
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute('INSERT INTO buckets (project, bucket) VALUES (%s, %s)'
                        ' ON CONFLICT DO NOTHING',
                        (project, bucket_name))


def query_buckets(project: str) -> Set[str]:
    """ Fetches a set of bucket names in a given project.

    Args:
        project: A string containing the project ID.
    Returns:
        A set of strings containing bucket names.
    """
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute('SELECT bucket FROM buckets WHERE project = %s',
                        (project,))
            buckets = {result[0] for result in cur.fetchall()}

        pg_connection.rollback()
    return buckets


def set_token(token: str, user_id: str, expiration: datetime.datetime) -> None:
    """ Defines a valid token.

    Args:
        token: A string containing the token ID.
        user_id: A string containing the user ID.
        expiration: A datetime object specifying the token expiration.
    """
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute('INSERT INTO tokens (token, user_id, expiration) '
                        'VALUES (%s, %s, %s)',
                        (token, user_id, expiration))


def get_user(token: str) -> str:
    """ Retrieves a user dictionary from a given token.

    Args:
        token: A string containing the token ID.
    Raises:
        TokenNotFound: Indicates that the token can't be found.
        TokenExpired: Indicates that the token has expired.
    """
    # Check if the token is already cached.
    if token in active_tokens:
        if (datetime.datetime.now(datetime.timezone.utc) <=
                active_tokens[token].expiration):
            return active_tokens[token].user
        raise TokenExpired('Token expired.')

    # Try to fetch the token from Postgres.
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute('SELECT user_id, expiration FROM tokens WHERE token = %s',
                        (token,))
            result = cur.fetchone()

        pg_connection.rollback()

    if result is None:
        raise TokenNotFound('Token not found.')

    user, expiration = result
    if datetime.datetime.now(datetime.timezone.utc) > expiration:
        raise TokenExpired('Token expired.')

    active_tokens[token] = Token(user, expiration)
    return active_tokens[token].user


def upsert_upload_state(upload_id: str, state: UploadState) -> None:
    """ Stores or updates state for a given upload ID.

    Args:
        upload_id: A string specifying the upload ID.
        state: A dictionary containing the upload state.
    """
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute('SELECT state FROM uploads WHERE id = %s', (upload_id,))
            result = cur.fetchone()
            if result is None:
                new_state = state
            else:
                new_state = json.loads(result[0])
                new_state.update(state)

            cur.execute('INSERT INTO uploads (id, state) VALUES (%s, %s) '
                        'ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state',
                        (upload_id, json.dumps(new_state)))


def get_upload_state(upload_id: str) -> UploadState:
    """ Fetches state for a given upload ID.

    Args:
        upload_id: A string specifying the upload ID.
    Returns:
        A dictionary containing the upload state.
    """
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute('SELECT state FROM uploads WHERE id = %s', (upload_id,))
            result = cur.fetchone()

        pg_connection.rollback()

    if result is None:
        raise UploadNotFound('Invalid upload_id.')

    return json.loads(result[0])


def get_completed_ranges(upload_request: MultiPartUpload) -> Ranges:
    """ Fetches list of tuples specifying completed ranges for an upload.

    Args:
        upload_request: A MultiPartUpload object.
    Returns:
        A list of tuples specifying completed byte ranges.
    """
    def drift(index_part: Tuple[int, Part]):
        index, part = index_part
        return index - part.part_number

    completed_ranges: List[Tuple[int, int]] = []
    group: Any
    for _, group in itertools.groupby(
            enumerate(cast(Iterable, upload_request)), drift):
        group = list(group)
        first_part = group[0][1]
        part_size = first_part.size
        start_of_range = (first_part.part_number - 1) * part_size

        last_part = group[-1][1]
        start_of_last_part = (last_part.part_number - 1) * part_size
        end_of_last_part = start_of_last_part + last_part.size - 1

        completed_ranges.append((start_of_range, end_of_last_part))
    return tuple(completed_ranges)


def completed_bytes(completed_ranges: Ranges) -> int:
    """ Fetches the total number of bytes stored for an upload.

    Args:
        completed_ranges: A tuple of tuples specifying the start and end bytes
            of completed parts.
    Returns:
        An integer specifying the total number of completed bytes.
    """
    return sum([end - start + 1 for start, end in completed_ranges])


def get_request_from_state(upload_id: str, upload_state: UploadState,
                           bucket: Bucket, policy: Optional[str]=None
                           ) -> MultiPartUpload:
    """ Fetches or creates a MultiPartUpload object for an upload ID.

    Args:
        upload_id: A string specifying the upload ID.
        upload_state: A dictionary containing upload state.
        bucket: A boto Bucket object.
        policy: Policy to use if initiating upload
    """
    upload_request: MultiPartUpload
    if upload_state['status'] == UploadStates.NEW:
        metadata = None
        if 'content-type' in upload_state:
            metadata = {'Content-Type': upload_state['content-type']}
        upload_request = bucket.initiate_multipart_upload(
            upload_state['object'],
            metadata=metadata,
            policy=policy)
        new_state = {'status': UploadStates.IN_PROGRESS,
                     'object': upload_state['object'],
                     'id': upload_request.id}
        upsert_upload_state(upload_id, new_state)
    else:
        upload_request = MultiPartUpload(bucket=bucket)
        upload_request.id = upload_state['id']
        upload_request.key_name = upload_state['object']
    return upload_request


def calculate_md5(key: Key) -> bytes:
    """ Calculates an MD5 digest for an object.

    Args:
        key: A boto Key object.
    Returns:
        A bytes object containing the MD5 digest.
    """
    md5_hash = hashlib.md5()
    while True:
        object_data = key.read(size=config['READ_SIZE'])
        if len(object_data) == 0:
            break
        md5_hash.update(object_data)
    return md5_hash.digest()


def rfc3339_format(datetime_value: datetime.datetime, datestr: str) -> Optional[str]:
    """ Get an RFC 3339 format date.

    Args:
        datetime_value: A datetime object. If None datestr is used.
        datestr: Text date in HTTP format (RFC 1123/2822)
    Returns:
        A formatted date or None if not available.
    """
    if not datetime_value:
        if not datestr:
            return None
        datetime_tuple = email_utils.parsedate(datestr)
        if datetime_tuple:
            timestamp = time.mktime(datetime_tuple)
            datetime_value = datetime.datetime.fromtimestamp(timestamp)

    if not datetime_value:
        return None

    datetime_value = datetime_value.replace(tzinfo=datetime.timezone.utc)
    return datetime_value.isoformat()


def set_object_metadata(key: Key, data: ObjectMetadata) -> None:
    """ Updates object metadata.

    Args:
        key: A boto Key object.
        data: A dictionary containing object metadata.
    """
    bucket_name = key.bucket.name
    object_name = key.name
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute('INSERT INTO object_metadata (bucket, object, metadata) '
                        'VALUES (%s, %s, %s) '
                        'ON CONFLICT (bucket, object) '
                        'DO UPDATE SET metadata = EXCLUDED.metadata',
                        (bucket_name, object_name, json.dumps(data)))


def get_object_metadata(key: Key) -> ObjectMetadata:
    """ Fetches object metadata.

    Args:
        key: A boto Key object.
    Returns:
        A dictionary containing object metadata.
    """
    bucket_name = key.bucket.name
    object_name = key.name
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute('SELECT metadata FROM object_metadata '
                        'WHERE bucket = %s AND object = %s',
                        (bucket_name, object_name))
            result = cur.fetchone()

        pg_connection.rollback()

    if result is None:
        return {}

    return json.loads(result[0])


def delete_object_metadata(key: Key) -> None:
    """ Deletes an object's metadata.

    Args:
        key: A boto Key object.
    """
    bucket_name = key.bucket.name
    object_name = key.name
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute('DELETE FROM object_metadata '
                        'WHERE bucket = %s AND object = %s',
                        (bucket_name, object_name))


def clean_tokens() -> int:
    """ Clean up expired token metadata

    """
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute('DELETE FROM tokens WHERE '
                        'expiration < CURRENT_TIMESTAMP')
            return cur.rowcount


def clean_uploads() -> int:
    """ Clean up expired token metadata

    """
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute('DELETE FROM uploads WHERE '
                        'created < (CURRENT_TIMESTAMP - INTERVAL %s)',
                        (datetime.timedelta(7),))
            return cur.rowcount
