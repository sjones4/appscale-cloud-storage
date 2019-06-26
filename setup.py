from setuptools import setup

setup(
    name='appscale-cloud-storage',
    version='0.1.0',
    description='A GCS-compatible storage server',
    license='Apache License 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3'
    ],
    keywords='appscale cloud storage gcs',
    packages=['appscale', 'appscale.cloud_storage',
              'appscale.cloud_storage.xml'],
    install_requires=[
        'boto',
        'flask',
        'oauth2client',
        'psycopg2-binary',
        'python-dateutil',
        'Werkzeug'
    ],
    entry_points={'console_scripts': [
        'appscale-cloud-storage-prime=appscale.cloud_storage.prime:prime',
        'appscale-cloud-storage-link=appscale.cloud_storage.link:link',
        'appscale-cloud-storage-clean=appscale.cloud_storage.clean:clean'
    ]}
)
