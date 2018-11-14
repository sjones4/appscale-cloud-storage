import datetime

EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)

# HTTP Status Codes
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_NO_CONTENT = 204
HTTP_PARTIAL_CONTENT = 206
HTTP_RESUME_INCOMPLETE = 308
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
HTTP_CONFLICT = 409
HTTP_RANGE_NOT_SATISFIABLE = 416
HTTP_ERROR = 500
HTTP_NOT_IMPLEMENTED = 501
