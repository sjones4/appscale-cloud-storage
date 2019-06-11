import base64
import binascii
import dateutil.parser
import math
import random
from boto.exception import S3ResponseError
from boto.s3.key import Key
from flask import Response
from flask import current_app
from flask import request
from io import BytesIO

from .decorators import authenticate_xml
from ..constants import HTTP_BAD_REQUEST
from ..constants import HTTP_CREATED
from ..constants import HTTP_NOT_FOUND
from ..constants import HTTP_NOT_IMPLEMENTED
from ..constants import HTTP_NO_CONTENT
from ..constants import HTTP_RANGE_NOT_SATISFIABLE
from ..constants import HTTP_RESUME_INCOMPLETE
from ..objects import read_object
from ..utils import UploadNotFound
from ..utils import UploadStates
from ..utils import calculate_md5
from ..utils import completed_bytes
from ..utils import delete_object_metadata
from ..utils import error
from ..utils import get_completed_ranges
from ..utils import get_object_metadata
from ..utils import get_request_from_state
from ..utils import get_upload_state
from ..utils import object_as_xml
from ..utils import set_object_metadata
from ..utils import upsert_upload_state
from ..utils import xml_error


RESPONSE_NS = 'http://doc.s3.amazonaws.com/2006-03-01'


def key_as_content(key):
    return {'Key': key.name, 'LastModified': key.last_modified, 'ETag': key.etag, 'Size': key.size}


@authenticate_xml
def list_objects(conn, bucket_name, **kwargs):
    current_app.logger.debug('headers: {}'.format(request.headers))
    """ Retrieves a list of objects.

    Args:
        conn: An S3Connection instance.
        bucket_name: A string specifying a bucket name.
    Returns:
        An XML string representing an object listing.
    """
    try:
        bucket = conn.get_bucket(bucket_name)
    except S3ResponseError as s3_error:
        if s3_error.status == HTTP_NOT_FOUND:
            return xml_error('NoSuchBucket', 'The specified bucket does not exist.', HTTP_NOT_FOUND)
        raise s3_error

    response = {'Name': bucket_name, 'IsTruncated': 'false'}
    response['Contents'] = [key_as_content(key) for key in bucket.list()]

    return Response(object_as_xml(response, 'ListBucketResult', RESPONSE_NS), mimetype='application/xml')


@authenticate_xml
def download_object(conn, bucket_name, object_name, **kwargs):
    current_app.logger.debug('headers: {}'.format(request.headers))

    unsupported_headers = ('If-Match', 'If-Modified-Since', 'If-None-Match',
                           'If-Unmodified-Since')
    for header in unsupported_headers:
        if header in request.headers:
            return error('The {} header is not supported.'.format(header),
                         HTTP_NOT_IMPLEMENTED)

    boto_headers = None
    if 'Range' in request.headers:
        boto_headers = {'Range': request.headers['Range']}

    try:
        bucket = conn.get_bucket(bucket_name)
    except S3ResponseError as s3_error:
        if s3_error.status == HTTP_NOT_FOUND:
            return error('Not Found', HTTP_NOT_FOUND)
        raise s3_error

    key = bucket.get_key(object_name)

    if key is None:
        return error('Not Found', HTTP_NOT_FOUND)

    try:
        key.open_read(headers=boto_headers)
    except S3ResponseError as s3_error:
        if s3_error.status == HTTP_RANGE_NOT_SATISFIABLE:
            return xml_error(
                code='InvalidRange',
                message='The requested range cannot be satisfied.',
                details=boto_headers,
                http_code=HTTP_RANGE_NOT_SATISFIABLE)
        raise s3_error

    headers = dict(key.resp.getheaders())
    current_app.logger.debug('s3 inbound headers: {}'.format(headers))
    response = Response(read_object(key, current_app.config['READ_SIZE']))
    response.headers['Content-Type'] = key.content_type
    response.headers['Last-Modified'] = key.last_modified
    response.headers['x-goog-stored-content-length'] = key.size
    if 'Content-Length' in headers:
      response.headers['Content-Length'] = headers['Content-Length']

    # Multipart uploads do not have MD5 metadata by default.
    if key.md5 is not None:
        response.headers['ETag'] = '"{}"'.format(key.md5)
    elif '-' not in key.etag:
        response.headers['ETag'] = '"{}"'.format(key.etag)
    else:
        metadata = get_object_metadata(key)
        md5 = binascii.hexlify(base64.b64decode(metadata['md5Hash']))
        response.headers['ETag'] = '"{}"'.format(md5.decode())
    return response


@authenticate_xml
def remove_object(conn, bucket_name, object_name, **kwargs):
    """ Deletes an object and its metadata.

    Args:
        bucket_name: A string specifying a bucket name.
        object_name: A string specifying an object name.
    """
    try:
        bucket = conn.get_bucket(bucket_name)
    except S3ResponseError as s3_error:
        if s3_error.status == HTTP_NOT_FOUND:
            return error('Not Found', HTTP_NOT_FOUND)
        raise s3_error

    # TODO: Do the following lookup and delete under a lock.
    key = bucket.get_key(object_name)
    if key is None:
        return error('Not Found', HTTP_NOT_FOUND)

    delete_object_metadata(key)
    key.delete()
    return '', HTTP_NO_CONTENT


@authenticate_xml
def post_object(conn, bucket_name, object_name, **kwargs):
    current_app.logger.debug('headers: {}'.format(request.headers))

    if request.headers['x-goog-resumable'] == 'start':
        new_upload_id = ''.join(
            random.choice(current_app.config['RESUMABLE_ID_CHARS'])
            for _ in range(current_app.config['RESUMABLE_ID_LENGTH']))
        current_app.logger.debug('new upload_id: {}, object: {}'.format(
            new_upload_id, object_name))
        state = {'object': object_name, 'status': UploadStates.NEW}
        if 'Content-Type' in request.headers:
            state['content-type'] = request.headers['Content-Type']
        upsert_upload_state(new_upload_id, state)

        redirect = request.url_root + '{bucket}/{object}?upload_id={id}'.\
            format(bucket=bucket_name, object=object_name, id=new_upload_id)
        response = Response('', status=HTTP_CREATED)
        response.headers['Location'] = redirect
        response.headers['X-GUploader-UploadID'] = new_upload_id
        del response.headers['Content-Type']
        return response

    return '', HTTP_NOT_IMPLEMENTED


@authenticate_xml
def put_object(conn, bucket_name, object_name, **kwargs):
    current_app.logger.debug('headers: {}'.format(request.headers))

    if 'X-Goog-Copy-Source' in request.headers:
        source = request.headers['X-Goog-Copy-Source']
        try:
            src_bucket_name = source.split('/')[1]
            src_object_name = '/'.join(source.split('/')[2:])
        except IndexError:
            return error('Invalid source object.', HTTP_BAD_REQUEST)

        src_bucket = conn.get_bucket(src_bucket_name)
        src_key = src_bucket.get_key(src_object_name)
        last_modified = dateutil.parser.parse(src_key.last_modified)

        dest_bucket = conn.get_bucket(bucket_name)
        new_key = dest_bucket.copy_key(object_name, src_bucket_name,
                                       src_object_name)

        response_xml = """
        <?xml version='1.0' encoding='UTF-8'?>
        <CopyObjectResult>
          <LastModified>{last_mod}</LastModified>
          <ETag>{etag}</ETag>
        </CopyObjectResult>
        """.strip().format(
            last_mod=last_modified.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            etag=new_key.etag)
        response = Response(response_xml)
        response.headers['ETag'] = new_key.etag
        response.headers['Content-Type'] = 'text/html'
        return response

    upload_id = request.args.get('upload_id', None)
    if upload_id is None:
        headers = None
        if 'Content-Type' in request.headers:
            headers = {'Content-Type': request.headers['Content-Type']}
        content = request.data

        bucket = conn.get_bucket(bucket_name)
        key = Key(bucket, object_name)
        key.set_contents_from_string(content, headers=headers)
        response = Response('')
        response.headers['ETag'] = key.etag
        return response
    else:
        try:
            upload_state = get_upload_state(upload_id)
        except UploadNotFound as state_error:
            return error(str(state_error), HTTP_BAD_REQUEST)

    request_length = int(request.headers['Content-Length'])
    if request_length < 1:
        return error('Content-Length must be greater than 0.',
                     HTTP_BAD_REQUEST)
    if 'Content-Range' in request.headers:
        unit, content_range = request.headers['Content-Range'].split()
        if unit != 'bytes':
            return error('Content-Range must be specified in bytes.',
                         HTTP_BAD_REQUEST)
    else:
        content_range = '0-{}/{}'.format(request_length - 1, request_length)

    current_portion, total_length = content_range.split('/')
    bucket = conn.get_bucket(bucket_name)
    if current_portion == '*':
        if upload_state['status'] == UploadStates.COMPLETE:
            # TODO: Check what GAE returns.
            return ''
        upload_request = get_request_from_state(
            upload_id, upload_state, bucket)

        if total_length != '*':
            try:
                total_length = int(total_length)
            except ValueError:
                return error('Invalid Content-Range.', HTTP_BAD_REQUEST)
            completed_ranges = get_completed_ranges(upload_request)
            if completed_bytes(completed_ranges) == total_length:
                upload_request.complete_upload()
                key = bucket.get_key(object_name)
                md5 = calculate_md5(key)

                new_state = {'status': UploadStates.COMPLETE,
                             'object': object_name}
                upsert_upload_state(upload_id, new_state)

                key.md5 = binascii.hexlify(md5)
                if 'content-type' in upload_state:
                    metadata = {'Content-Type': upload_state['content-type']}
                    key.copy(bucket_name, object_name, metadata=metadata)
                set_object_metadata(key, {
                    'md5Hash': base64.b64encode(md5).decode()})
                return ''

        response = Response('', status=HTTP_RESUME_INCOMPLETE)
        range_strings = ['{}-{}'.format(start, end) for start, end
                         in get_completed_ranges(upload_request)]
        if range_strings:
            response.headers['Range'] = 'bytes=' + ','.join(range_strings)
        return response

    if total_length == '*':
        total_length = None
    else:
        try:
            total_length = int(total_length)
        except ValueError:
            return error('Invalid Content-Range.', HTTP_BAD_REQUEST)

    try:
        start, end = [int(value) for value in current_portion.split('-')]
    except ValueError:
        return error('Invalid Content-Range.', HTTP_BAD_REQUEST)

    chunk_size = current_app.config['UPLOAD_CHUNK_SIZE']
    if ((end - start + 1) % chunk_size != 0 and
            (total_length is None or end != (total_length - 1))):
        return error('Non-termninal chunk sizes must be multiples '
                     'of {}'.format(chunk_size), HTTP_BAD_REQUEST)

    request_chunks = math.ceil(request_length / chunk_size)
    chunk_start = start / chunk_size + 1
    if chunk_start != int(chunk_start):
        return error(
            'Content-Range start must be a multiple of {}'.format(chunk_size))
    chunk_start = int(chunk_start)

    upload_request = get_request_from_state(upload_id, upload_state, bucket)

    for chunk_num in range(chunk_start, chunk_start + request_chunks):
        offset = chunk_size * (chunk_num - 1)
        if total_length is not None:
            current_chunk_size = min(chunk_size, total_length - offset)
        else:
            current_chunk_size = chunk_size
        # Boto requires a file object when uploading a part, but Flask's
        # request.stream cannot seek.
        chunk = BytesIO(request.stream.read(chunk_size))
        upload_request.upload_part_from_file(chunk, part_num=chunk_num,
                                             size=current_chunk_size)

    completed_ranges = get_completed_ranges(upload_request)
    if (total_length is not None and
                completed_bytes(completed_ranges) == total_length):
        # Ideally, the MD5 would be calculated before the request is finalized,
        # but there doesn't seem to be a way to fetch part data beforehand.
        upload_request.complete_upload()
        key = bucket.get_key(object_name)
        md5 = calculate_md5(key)

        new_state = {'status': UploadStates.COMPLETE, 'object': object_name}
        upsert_upload_state(upload_id, new_state)

        key.md5 = binascii.hexlify(md5)
        if 'content-type' in upload_state:
            metadata = {'Content-Type': upload_state['content-type']}
            key.copy(bucket_name, object_name, metadata=metadata)
        set_object_metadata(key, {'md5Hash': base64.b64encode(md5).decode()})
        # TODO: Check what GAE returns.
        return ''

    response = Response('', status=HTTP_RESUME_INCOMPLETE)
    range_strings = ['{}-{}'.format(start, end)
                     for start, end in completed_ranges]
    response.headers['Range'] = 'bytes=' + ','.join(range_strings)
    return response
