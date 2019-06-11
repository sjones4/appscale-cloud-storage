""" Clean up expired metadata. """

import argparse

from .utils import (clean_tokens, clean_uploads)


def clean():
    """ Clean up expired metadata.
    """

    parser = argparse.ArgumentParser(
        description='Perform periodic metadata clean up')
    parser.add_argument('--tokens', '-t', action='store_true',
                        help='Clean token metadata')
    parser.add_argument('--uploads', '-u', action='store_true',
                        help='Clean upload metadata')
    args = parser.parse_args()
    if not args.tokens and not args.uploads:
        args.tokens = True
        args.uploads = True

    if args.tokens:
        tokens_expired = clean_tokens()
        print('Expired {} tokens'.format(tokens_expired))

    if args.uploads:
        uploads_expired = clean_uploads()
        print('Expired {} uploads'.format(uploads_expired))
