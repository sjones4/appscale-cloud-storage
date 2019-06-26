import string

# The number of characters in an access token.
ACCESS_TOKEN_LENGTH = 77

# The S3 credentials to use for performing administrative S3 operations.
S3_ADMIN_CREDS = {'access_key': '', 'secret_key': ''}

# The S3 endpoint to use as a storage backend.
S3_HOST = 'localhost'
S3_PORT = 8080
S3_USE_SSL = False

# The host and port that AppScale Cloud Storage should serve on.
SERVER_NAME = 'localhost:5000'

# The number of seconds a token should be good for.
TOKEN_EXPIRATION = 3600

# The accounts that are authorized to use AppScale Cloud Storage. The keys
# correspond to client_email in your JSON service credentials file. The values
# are dictionaries specifying the path to the certificate associated with the
# service credentials and existing AWS-style credentials to use with that
# account.
USERS = {}

# The chunk size to use when fetching object data from S3.
READ_SIZE = 1 << 20

# The length of upload ID string.
RESUMABLE_ID_LENGTH = 14

# The characters used when generating upload ID strings.
RESUMABLE_ID_CHARS = string.ascii_uppercase + string.digits + '_'

# The chunk size to use when uploading data to S3. S3 requires a minimum of
# 5MB for non-terminal chunks, but GCS allows 256KB chunks.
UPLOAD_CHUNK_SIZE = 5 << 20
