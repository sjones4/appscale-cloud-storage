""" Add metadata linking project to bucket. """

import argparse

from .utils import index_bucket


def link():
    """ Link a bucket to a project, typically you would link a bucket to one
        project. """

    parser = argparse.ArgumentParser(description='Link a project to a bucket')
    parser.add_argument('--bucket', '-b', required=True, help='The bucket to be linked')
    parser.add_argument('--project', '-p', required=True, help='The project to link to')
    args = parser.parse_args()
    index_bucket(args.bucket, args.project)
