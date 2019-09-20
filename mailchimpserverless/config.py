"""
This module contains all app configurations for testing, development,
and production.

________________________________________________________________________

"""


import os


class BaseConfig(object):
    SECRET_KEY = os.environ['SECRET_KEY']
    MCVOD_API_USERNAME = os.environ['MCVOD_API_USERNAME']
    DB_NAME = os.environ['DB_NAME']
    DB_HOST = os.environ['DB_HOST']
    DB_USER = os.environ['DB_USER']
    DB_PASSWORD = os.environ['DB_PASSWORD']
    SQLALCHEMY_DATABASE_URI = (
        f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAILCHIMP_DC = os.environ['MAILCHIMP_DC']
    MAILCHIMP_BASE_URL = f'https://{MAILCHIMP_DC}.api.mailchimp.com/3.0'
    MAILCHIMP_KEY = os.environ['MAILCHIMP_KEY']
    MAILCHIMP_API_KEY = f'{MAILCHIMP_KEY}-{MAILCHIMP_DC}'
    MAILCHIMP_USERNAME = os.environ['MAILCHIMP_USERNAME']
    MAILCHIMP_TIMEOUT = 30.0
    # TO DO useragent
    MAILCHIMP_LIST_ID = os.environ['MAILCHIMP_LIST_ID']
    AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']
    AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']
    AWS_TASK_QUEUE = os.environ['AWS_TASK_QUEUE']
    AWS_REGION = os.environ['AWS_REGION']
    broker_url = f'sqs://{AWS_ACCESS_KEY_ID}:{AWS_SECRET_ACCESS_KEY}@'
    broker_transport_options = {
        'region': AWS_REGION,
        'polling_interval': 20
    }
    accept_content = ['application/json']
    worker_enable_remote_control = False
    worker_send_task_events = False
    task_default_queue = AWS_TASK_QUEUE
    task_serializer = 'json'
    result_backend = None
    result_serializer = 'json'
    BROKER = broker_url


class TestConfig(BaseConfig):
    DEBUG = False
    TESTING = True
    DEVELOPMENT = False


class LocalConfig(BaseConfig):
    DEBUG = True
    TESTING = False
    DEVELOPMENT = True


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    TESTING = False
    DEVELOPMENT = True


class ProductionConfig(BaseConfig):
    DEBUG = False
    TESTING = False
    DEVELOPMENT = False

