#!/usr/bin/env python3

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from appscale.cloud_storage import batches
from appscale.cloud_storage import buckets
from appscale.cloud_storage import oauth
from appscale.cloud_storage import objects
from appscale.cloud_storage import utils
from appscale.cloud_storage.xml import buckets as xml_buckets
from appscale.cloud_storage.xml import objects as xml_objects

app = Flask(__name__)
app.config.from_object('appscale.cloud_storage.config')
try:
    app.config.from_envvar('APPSCALE_CLOUD_STORAGE_SETTINGS')
except RuntimeError:
    app.logger.info('No custom settings specified.')
app.wsgi_app = ProxyFix(app.wsgi_app)

objects.ACL_DEFAULT = app.config.get('S3_OBJECT_ACL', objects.ACL_DEFAULT)

utils.pg_connector = utils.PostgresConnector(**app.config['POSTGRES_DB'])
utils.config = app.config

#
# Access Tokens
#
app.add_url_rule('/o/oauth2/token',
                 view_func=oauth.get_token, methods=['POST'],
                 subdomain='<subdomain>')

#
# JSON API
#

# Request batching
app.add_url_rule('/batch/storage/v1',
                 view_func=batches.batch, methods=['POST'],
                 subdomain='<subdomain>')
app.add_url_rule('/null',  # dataflow client does not configure batch path
                 view_func=batches.batch, methods=['POST'],
                 subdomain='<subdomain>')

# Buckets
app.add_url_rule('/storage/v1/b',
                 view_func=buckets.list_buckets, methods=['GET'],
                 subdomain='<subdomain>')
app.add_url_rule('/storage/v1/b',
                 view_func=buckets.insert_bucket, methods=['POST'],
                 subdomain='<subdomain>')
app.add_url_rule('/storage/v1/b/<bucket_name>',
                 view_func=buckets.get_bucket, methods=['GET'],
                 subdomain='<subdomain>')
app.add_url_rule('/storage/v1/b/<bucket_name>',
                 view_func=buckets.delete_bucket, methods=['DELETE'],
                 subdomain='<subdomain>')

# Objects
app.add_url_rule('/storage/v1/b/<bucket_name>/o',
                 view_func=objects.list_objects, methods=['GET'],
                 subdomain='<subdomain>')
app.add_url_rule('/storage/v1/b/<bucket_name>/o/<path:object_name>',
                 view_func=objects.get_object, methods=['GET'],
                 subdomain='<subdomain>')
app.add_url_rule('/download/storage/v1/b/<bucket_name>/o/<path:object_name>',
                 view_func=objects.get_object, methods=['GET'],
                 subdomain='<subdomain>')
app.add_url_rule('/storage/v1/b/<bucket_name>/o/<path:object_name>',
                 view_func=objects.delete_object, methods=['DELETE'],
                 subdomain='<subdomain>')
app.add_url_rule('/upload/storage/v1/b/<bucket_name>/o',
                 view_func=objects.insert_object, methods=['POST'],
                 subdomain='<subdomain>')
app.add_url_rule('/upload/storage/v1/b/<bucket_name>/o',
                 view_func=objects.resumable_insert, methods=['PUT'],
                 subdomain='<subdomain>')
app.add_url_rule('/storage/v1/b/<bucket_name>/o/<path:object_name>'
                 '/copyTo/b/<dest_bucket_name>/o/<path:dest_object_name>',
                 view_func=objects.copy_object, methods=['POST'],
                 subdomain='<subdomain>')

#
# XML API
#

# Buckets
app.add_url_rule('/<bucket_name>', strict_slashes=False,
                 endpoint='xml_bucket_put',
                 view_func=xml_buckets.create_bucket, methods=['PUT'],
                 subdomain='<subdomain>')
app.add_url_rule('/<bucket_name>', strict_slashes=False,
                 endpoint='xml_bucket_delete',
                 view_func=xml_buckets.delete_bucket, methods=['DELETE'],
                 subdomain='<subdomain>')

# Objects
app.add_url_rule('/<bucket_name>', strict_slashes=False,
                 endpoint='xml_object_list',
                 view_func=xml_objects.list_objects, methods=['GET'],
                 subdomain='<subdomain>')
app.add_url_rule('/<bucket_name>/<path:object_name>',
                 endpoint='xml_object_post',
                 view_func=xml_objects.post_object, methods=['POST'],
                 subdomain='<subdomain>')
app.add_url_rule('/<bucket_name>/<path:object_name>',
                 endpoint='xml_object_put',
                 view_func=xml_objects.put_object, methods=['PUT'],
                 subdomain='<subdomain>')
app.add_url_rule('/<bucket_name>/<path:object_name>',
                 endpoint='xml_object_get',
                 view_func=xml_objects.download_object, methods=['GET'],
                 subdomain='<subdomain>')
app.add_url_rule('/<bucket_name>/<path:object_name>',
                 endpoint='xml_object_delete',
                 view_func=xml_objects.remove_object, methods=['DELETE'],
                 subdomain='<subdomain>')
