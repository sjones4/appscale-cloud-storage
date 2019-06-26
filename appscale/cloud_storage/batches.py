from email.generator import Generator
from email.mime.multipart import MIMEMultipart
from email.mime.nonmultipart import MIMENonMultipart
from email.parser import FeedParser
from flask import current_app
from flask import request
from flask import Response
from io import StringIO
from werkzeug.datastructures import Headers

from .constants import HTTP_BAD_REQUEST
from .decorators import authenticate
from .utils import error


@authenticate
def batch(conn, **kwargs):
    """ Handle request batch.

    Args:
        conn: An S3Connection instance.
    Returns:
        A multipart response for each batched message.
    """
    header = 'Content-Type: %s\r\n\r\n' % request.content_type
    current_app.logger.debug('content-type header: {}'.format(header))
    current_app.logger.debug('request data: {}'.format(request.data))

    parser = FeedParser()
    parser.feed(header)
    parser.feed(request.get_data(as_text=True))
    mime_request = parser.close()

    if not mime_request.is_multipart():
        return error('Invalid content type for batch request: {}'
                     .format(request.content_type), HTTP_BAD_REQUEST)

    parts = mime_request.get_payload()
    for part in parts:
        if 'application/http' != part.get_content_type():
            return error('Invalid content type for batch part: {}'
                         .format(part.get_content_type()), HTTP_BAD_REQUEST)

    mime_response = MIMEMultipart()
    setattr(mime_response, '_write_headers', lambda self: None)

    for part in parts:
        current_app.logger.debug('part payload: {}'.format(part.get_payload()))
        method, path, headers, body = _deserialize_request(part.get_payload())
        current_app.logger.debug('part method: {}'.format(method))
        current_app.logger.debug('part path: {}'.format(path))
        current_app.logger.debug('part headers: {}'.format(headers))
        current_app.logger.debug('part body: {}'.format(body))

        with current_app.app_context():
            with current_app.test_request_context(path, method=method,
                                                  headers=headers, data=body):
                try:
                    rv = current_app.preprocess_request()
                    if rv is None:
                        rv = current_app.dispatch_request()
                except Exception as e:
                    current_app.logger.debug('part dispatch error: {}'.format(e))
                    rv = current_app.handle_user_exception(e)

                response = current_app.make_response(rv)
                response = current_app.process_response(response)

                mime_part = MIMENonMultipart('application', 'http')
                mime_part.set_payload(_serialize_response(response))
                mime_response.attach(mime_part)

    mime_out = StringIO()
    gen = Generator(mime_out, maxheaderlen=0)
    gen.flatten(mime_response, unixfrom=False)

    return Response(mime_out.getvalue(), mimetype=mime_response['Content-Type'])


def _serialize_response(response):
    """Convert a Response object into a string.

    Args:
      response: Response, the response to serialize.

    Returns:
      The response as a string in application/http format.
    """
    current_app.logger.debug('serializing response: {}'.format(response))

    # Construct status line
    status_line = '{} {}\r\n'.format(response.status_code, response.status)
    maintype, subtype = response.headers.get('Content-Type',
                                             'application/json').split('/')
    msg = MIMENonMultipart(maintype, subtype)
    headers = Headers(response.headers)

    if 'Content-Type' in headers:
        del headers['Content-Type']

    for key, value in headers:
        msg[key] = value

    if response.data is not None:
        msg.set_payload(response.data)

    headers_body = msg.as_string(False)
    if response.data is None:
        headers_body = headers_body[:-2]

    current_app.logger.debug('response status: {}'.format(status_line))
    current_app.logger.debug('response headers/body: {}'.format(headers_body))
    return status_line + headers_body


def _deserialize_request(payload):
    """Convert string to tuple of request parts

    Args:
      payload: string, headers and body as a string.

    Returns:
      A tuple of method, path, headers and body.
    """
    current_app.logger.debug('deserializing request: {}'.format(payload))
    request_line, payload = payload.split('\r\n', 1)
    method, path, http_version = request_line.split(' ', 2)

    current_app.logger.debug('deserializing payload: {}'.format(payload))
    parser = FeedParser()
    parser.feed(payload)
    msg = parser.close()
    headers_body = payload.split('\r\n\r\n', 1)
    body = headers_body[1] if 1 < len(headers_body) else None

    return method, path, Headers(msg.items()), body
