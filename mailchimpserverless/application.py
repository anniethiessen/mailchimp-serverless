"""
This module contains all app configurations, celery configurations, auth
configurations, MailChimp configurations, schemas, and routes.

________________________________________________________________________

"""


import os
import hashlib
from datetime import datetime, timedelta
from pytz import utc

from celery import Celery, group
from celery.utils.log import get_task_logger
from flask_httpauth import HTTPTokenAuth
from itsdangerous import JSONWebSignatureSerializer
from itsdangerous.exc import BadSignature
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import or_
from sqlalchemy.orm import relationship
from mailchimp3 import MailChimp
from mailchimp3.mailchimpclient import MailChimpError
from marshmallow import (
    Schema,
    ValidationError,
    post_load
)
from marshmallow.fields import (
    Boolean,
    DateTime,
    Email,
    Str
)
from marshmallow.validate import Length, OneOf
from werkzeug.utils import import_string

from flask import (
    Flask,
    jsonify,
    make_response,
    request
)


# <editor-fold desc="Initiations & Definitions">
application = Flask(__name__)
application.config.from_object(import_string(os.environ['CONFIG_CLASS'])())

auth = HTTPTokenAuth('Bearer')

authorized_users = [application.config['MCVOD_API_USERNAME']]
jws = JSONWebSignatureSerializer(application.config['SECRET_KEY'])

db = SQLAlchemy(application)
db.Model.metadata.reflect(db.engine)

celery = Celery(application.name, broker=application.config['BROKER'])
celery.conf.update(application.config)
logger = get_task_logger(__name__)


mailchimp_client = MailChimp(
    mc_api=application.config['MAILCHIMP_API_KEY'],
    mc_user=application.config['MAILCHIMP_USERNAME'],
    timeout=application.config['MAILCHIMP_TIMEOUT'],
)
mailchimp_list_id = application.config['MAILCHIMP_LIST_ID']
mailchimp_member_fields = [
    'id',
    'email_address',
    'merge_fields',
    'status',
    'timestamp_signup',
    'last_changed',
    'tags'
]
mailchimp_tag_groups = {
    'is_staff': {
        'verbose': 'staff',
        'options': [
            {
                'value': False,
                'verbose': 'No'
            },
            {
                'value': True,
                'verbose': 'Yes'
            }
        ]
    },
    'is_active': {
        'verbose': 'active',
        'options': [
            {
                'value': False,
                'verbose': 'No'
            },
            {
                'value': True,
                'verbose': 'Yes'
            }
        ]
    },
    'is_verified': {
        'verbose': 'verified',
        'options': [
            {
                'value': False,
                'verbose': 'No'
            },
            {
                'value': True,
                'verbose': 'Yes'
            }
        ]
    },
    'is_linked': {
        'verbose': 'linked',
        'options': [
            {
                'value': False,
                'verbose': 'No'
            },
            {
                'value': True,
                'verbose': 'Yes'
            }
        ]
    },
    'access_tier': {
        'verbose': 'tier',
        'options': [
            {
                'value': '0_FREE',
                'verbose': 'Free'
            },
            {
                'value': '1_DONOR',
                'verbose': 'Donor'
            },
            {
                'value': '2_GRANTED',
                'verbose': 'Granted'
            }
        ]
    }
}
# </editor-fold>


# <editor-fold desc="Models & Schemas">
class User(db.Model):
    __table__ = db.Model.metadata.tables['auth_user']
    profile = relationship(
        'Profile',
        uselist=False,
        back_populates="user"
    )

    def __repr__(self):
        return f"{self.email} :: {self.profile.mailchimp_member}"


class Profile(db.Model):
    __table__ = db.Model.metadata.tables['account_profile']
    user = relationship(
        'User',
        back_populates='profile'
    )

    def __repr__(self):
        return str(self.user)


class MemberSchema(Schema):
    email = Email(
        load_only=True,
        required=True,
        validate=Length(max=254)
    )
    first_name = Str(
        load_only=True,
        missing='',
        validate=Length(max=30)
    )
    last_name = Str(
        load_only=True,
        missing='',
        validate=Length(max=150)
    )
    status = Str(
        load_only=True,
        missing='subscribed'
    )
    date_joined = DateTime(
        load_only=True,
        required=True
    )
    is_staff = Boolean(
        load_only=True,
        required=True
    )
    is_active = Boolean(
        load_only=True,
        required=True
    )
    is_verified = Boolean(
        load_only=True,
        required=True
    )
    is_linked = Boolean(
        load_only=True,
        required=True
    )
    access_tier = Str(
        load_only=True,
        required=True,
        validate=OneOf(
            [
                option['value'] for option
                in mailchimp_tag_groups['access_tier']['options']
            ]
        )
    )

    @staticmethod
    def clean_tag_data(data):
        try:
            tag_list = []
            for _group, values in mailchimp_tag_groups.items():
                if _group in data:
                    value = data.pop(_group)
                    for option in values['options']:
                        status = (
                            'active' if option['value'] == value
                            else 'inactive'
                        )
                        name = f"{values['verbose']}: {option['verbose']}"
                        tag_list.append(
                            {
                                "name": name,
                                "status": status
                            }
                        )
            data['tags'] = tag_list
            return data
        except Exception:
            raise

    @staticmethod
    def clean_member_data(data):
        try:
            email_address = data.pop('email', None)
            if email_address:
                data['email_address'] = email_address

            merge_fields = {}
            first_name = data.pop('first_name', None)
            last_name = data.pop('last_name', None)
            if isinstance(first_name, str):
                merge_fields['FNAME'] = first_name
            if isinstance(last_name, str):
                merge_fields['LNAME'] = last_name
            if merge_fields:
                data['merge_fields'] = merge_fields

            date_joined = data.pop('date_joined', None)
            if isinstance(date_joined, datetime):
                date_joined = date_joined - timedelta(
                    seconds=date_joined.second,
                    microseconds=date_joined.microsecond
                )
                data['timestamp_signup'] = date_joined.replace(
                    tzinfo=utc).isoformat()

            return data
        except Exception:
            raise

    @post_load
    def clean_data(self, data, **kwargs):
        try:
            return self.clean_member_data(self.clean_tag_data(data))
        except Exception:
            raise
# </editor-fold>


# <editor-fold desc="MailChimp API Requests">
def list_mailchimp_members():
    try:
        return mailchimp_client.lists.members.all(
            list_id=mailchimp_list_id,
            get_all=True,
            fields=','.join(
                [f'members.{f}' for f in mailchimp_member_fields])
        )['members']
    except (MailChimpError, Exception):
        raise


def create_mailchimp_member(data):
    try:
        return mailchimp_client.lists.members.create(
            list_id=mailchimp_list_id,
            data=data
        )
    except (MailChimpError, Exception):
        raise


def retrieve_mailchimp_member(member_id):
    try:
        return mailchimp_client.lists.members.get(
            list_id=mailchimp_list_id,
            subscriber_hash=member_id,
            fields=','.join([f for f in mailchimp_member_fields])
        )
    except (MailChimpError, Exception):
        raise


def update_mailchimp_member(member_id, data):
    try:
        return mailchimp_client.lists.members.update(
            list_id=mailchimp_list_id,
            subscriber_hash=member_id,
            data=data
        )
    except (MailChimpError, Exception):
        raise


def update_mailchimp_member_tags(member_id, data):
    try:
        return mailchimp_client.lists.members.tags.update(
            list_id=mailchimp_list_id,
            subscriber_hash=member_id,
            data={'tags': data}
        )
    except (MailChimpError, Exception):
        raise


def delete_mailchimp_member(member_id):
    try:
        return mailchimp_client.lists.members.delete(
            list_id=mailchimp_list_id,
            subscriber_hash=member_id
        )
    except (MailChimpError, Exception):
        raise
# </editor-fold>


# # <editor-fold desc="Database Queries & Commits">
def get_email_md5_hash(email):
    md5_hash = hashlib.md5(email.encode('utf-8'))
    return md5_hash.hexdigest()


def get_unsynced_user_profile_query():
    return User.query.join(
        User.profile, aliased=True
    ).filter(
        ~User.username.contains('pac+'),
        ~Profile.is_synced
    )


def get_user_profile(user_id=None, member_id=None):
    try:
        query = get_unsynced_user_profile_query()

        if user_id:
            user = query.filter(
                User.id == user_id
            ).first()
        elif member_id:
            user = query.filter(
                Profile.mailchimp_member == member_id
            ).first()
        else:
            raise Exception("user_id or member_id required")
    except Exception:
        raise

    if not user:
        raise Exception("User not found")

    return user


def get_new_user_profiles():
    try:
        query = get_unsynced_user_profile_query()
        return query.filter(
            or_(
                Profile.mailchimp_member == None,
                Profile.mailchimp_member == ""
            )
        ).all()
    except Exception:
        raise


def get_updated_user_profiles():
    try:
        query = get_unsynced_user_profile_query()
        return query.filter(
            Profile.mailchimp_member.isnot(None),
            Profile.mailchimp_member != ""
        ).all()
    except Exception:
        raise


def get_user_profile_data(user):
    try:
        return {
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'date_joined': str(user.date_joined),
            'is_staff': bool(user.is_staff),
            'is_active': bool(user.is_active),
            'is_verified': bool(user.profile.is_verified),
            'is_linked': bool(user.profile.is_linked),
            'access_tier': user.profile.access_tier
        }
    except Exception:
        raise


def mark_user_profile_as_synced(user, member_id):
    try:
        user.profile.is_synced = True
        user.profile.mailchimp_member = member_id
        db.session.commit()
        return user
    except Exception:
        raise
# # </editor-fold>


# # <editor-fold desc="Celery Tasks">
@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(
        180.0,
        sync_members_task.s(),
        name='sync members'
    )


@celery.task
def create_member_task(user_id):
    try:
        with application.app_context():
            user = get_user_profile(user_id=user_id)
            data = get_user_profile_data(user)
            clean_data = MemberSchema().load(data)
            tag_data = clean_data.pop('tags', {})

            member = create_mailchimp_member(data=clean_data)
            msg = f"{member['email_address']} :: {member['id']} created"
            logger.info(msg)

            update_mailchimp_member_tags(member['id'], tag_data)
            msg = f"{member['email_address']} :: {member['id']} tags updated"
            logger.info(msg)

            user = mark_user_profile_as_synced(user, member['id'])
            msg = f"{user} synced"
            logger.info(msg)

            return member['id']
    except (ValidationError, MailChimpError, Exception) as err:
        msg = f"User: {user_id}, error: {err}"
        logger.exception(msg)
        return 'exception'


@celery.task
def update_member_task(member_id):
    try:
        user = get_user_profile(member_id=member_id)
        data = get_user_profile_data(user)
        clean_data = MemberSchema().load(data, partial=True)
        tag_data = clean_data.pop('tags', {})

        member = update_mailchimp_member(member_id, clean_data)
        msg = f"{member['email_address']} :: {member['id']} updated"
        logger.info(msg)

        update_mailchimp_member_tags(member['id'], tag_data)
        msg = f"{member['email_address']} :: {member['id']} tags updated"
        logger.info(msg)

        user = mark_user_profile_as_synced(user, member['id'])
        msg = f"{user} synced"
        logger.info(msg)

        return member['id']
    except (ValidationError, MailChimpError, Exception) as err:
        msg = f"Member: {member_id}, error: {err}"
        logger.exception(msg)
        return 'exception'


@celery.task
def delete_member_task(member_id):
    try:
        member = retrieve_mailchimp_member(member_id)
        delete_mailchimp_member(member_id)
        msg = f"{member['email_address']} :: {member['id']} deleted"
        logger.info(msg)

        return member['id']
    except (MailChimpError, Exception) as err:
        msg = f"Member: {member_id}, error: {err}"
        logger.exception(msg)
        return 'exception'


@celery.task
def sync_new_members_task():
    try:
        new_user_profiles = get_new_user_profiles()
        job_group = group(
            create_member_task.s(user.id)
            for user in new_user_profiles
        )
        job_group.apply_async()

        msg = "New Members Sync, complete"
        logger.info(msg)
        return msg
    except Exception as err:
        msg = f"New Members Sync, error: {err}"
        logger.exception(msg)
        return 'exception'


@celery.task
def sync_updated_members_task():
    try:
        updated_user_profiles = get_updated_user_profiles()
        job_group = group(
            update_member_task.s(member_id=user.profile.mailchimp_member)
            for user in updated_user_profiles
        )
        job_group.apply_async()

        msg = "Updated Members Sync, queued"
        logger.info(msg)
        return msg
    except Exception as err:
        msg = f"Updated Members Sync, error: {err}"
        logger.exception(msg)
        return 'exception'


@celery.task
def sync_members_task():
    try:
        sync_updated_members_task.delay()
        sync_new_members_task.delay()

        msg = "Updated Members Sync, queued"
        logger.info(msg)
        return msg
    except Exception as err:
        msg = f"Members Sync, error: {err}"
        logger.exception(msg)
        return 'exception'
# </editor-fold">


# <editor-fold desc="Auth Handlers">
@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


@auth.verify_token
def verify_token(token):
    try:
        data = jws.loads(token)
    except (BadSignature, Exception):
        return False

    if data.get('username', '') in authorized_users:
        return True
    else:
        return False
# </editor-fold>


# <editor-fold desc="Routes">
@application.route('/', methods=['GET'])
def index():
    try:
        return make_response(jsonify({'success': f"Hello MailChimp"}), 200)
    except Exception as err:
        return make_response(jsonify({'error': str(err)}), 400)


@application.route('/hash/<email>', methods=['GET'])
@auth.login_required
def retrieve_hash(email):
    try:
        md5_hash = hashlib.md5(email.encode('utf-8'))
        return make_response(jsonify({'success': md5_hash.hexdigest()}), 200)
    except Exception as err:
        return make_response(jsonify({'error': str(err)}), 400)


@application.route('/members', methods=['GET'])
@auth.login_required
def list_members():
    try:
        response = list_mailchimp_members()
        return make_response(jsonify(response), 200)
    except Exception as err:
        return make_response(jsonify({'error': str(err)}), 400)


@application.route('/members', methods=['POST'])
@auth.login_required
def create_member():
    try:
        if not (request.json and 'user_id' in request.json):
            return make_response(jsonify({'error': "user id required"}), 400)

        user = get_user_profile(user_id=request.json['user_id'])
        data = get_user_profile_data(user)
        clean_data = MemberSchema().load(data)
        tag_data = clean_data.pop('tags', {})

        member = create_mailchimp_member(data=clean_data)
        update_mailchimp_member_tags(member['id'], tag_data)
        user = mark_user_profile_as_synced(user, member['id'])
        success_msg = f"{member['email_address']} :: {member['id']} created"
        return make_response(jsonify({'success': success_msg}), 201)
    except (ValidationError, MailChimpError, Exception) as err:
        return make_response(jsonify({'error': str(err)}), 400)


@application.route('/members/<member_id>', methods=['GET'])
@auth.login_required
def retrieve_member(member_id):
    try:
        response = retrieve_mailchimp_member(member_id)
        return make_response(jsonify(response), 200)
    except Exception as err:
        return make_response(jsonify({'error': str(err)}), 400)


@application.route('/members/<member_id>', methods=['PATCH'])
@auth.login_required
def update_member(member_id):
    try:
        user = get_user_profile(member_id=member_id)
        data = get_user_profile_data(user)
        clean_data = MemberSchema().load(data, partial=True)
        tag_data = clean_data.pop('tags', {})

        member = update_mailchimp_member(member_id, clean_data)
        update_mailchimp_member_tags(member['id'], tag_data)
        user = mark_user_profile_as_synced(user, member['id'])
        success_msg = f"{member['email_address']} :: {member['id']} updated"
        return make_response(jsonify({'success': success_msg}), 200)
    except (ValidationError, MailChimpError, Exception) as err:
        return make_response(jsonify({'error': str(err)}), 400)


@application.route('/members/<member_id>', methods=['DELETE'])
@auth.login_required
def delete_member(member_id):
    try:
        member = retrieve_mailchimp_member(member_id)
        delete_mailchimp_member(member_id)
        success_msg = f"{member['email_address']} :: {member['id']} deleted"
        return make_response(jsonify({'success': success_msg}), 204)
    except (MailChimpError, Exception) as err:
        return make_response(jsonify({'error': str(err)}), 400)


@application.route('/members/sync', methods=['PUT'])
@auth.login_required
def sync_members():
    try:
        create_count = 0
        update_count = 0
        error_count = 0

        new_user_profiles = get_new_user_profiles()
        updated_user_profiles = get_updated_user_profiles()

        for user in updated_user_profiles:
            try:
                member_id = user.profile.mailchimp_member
                data = get_user_profile_data(user)
                clean_data = MemberSchema().load(data, partial=True)
                tag_data = clean_data.pop('tags', {})

                member = update_mailchimp_member(member_id, clean_data)
                update_mailchimp_member_tags(member['id'], tag_data)
                mark_user_profile_as_synced(user, member['id'])
                update_count += 1
            except (ValidationError, MailChimpError, Exception) as err:
                error_count += 1
                continue

        for user in new_user_profiles:
            try:
                data = get_user_profile_data(user)
                clean_data = MemberSchema().load(data)
                tag_data = clean_data.pop('tags', {})

                member = create_mailchimp_member(clean_data)
                update_mailchimp_member_tags(member['id'], tag_data)
                mark_user_profile_as_synced(user, member['id'])
                create_count += 1
            except (ValidationError, MailChimpError, Exception) as err:
                error_count += 1
                continue
        msg = (
            f"{create_count} created, "
            f"{update_count} updated, "
            f"{error_count} errors"
        )
        return make_response(jsonify({'success': msg}), 200)
    except Exception as err:
        return make_response(jsonify({'error': str(err)}), 400)


@application.route('/queue/members', methods=['POST'])
@auth.login_required
def queue_create_member():
    if not (request.json and 'user_id' in request.json):
        return make_response(jsonify({'error': "user id required"}), 400)

    try:
        create_member_task.delay(user_id=request.json['user_id'])
        return make_response(jsonify({'success': "Create in queue"}), 200)
    except Exception as err:
        return make_response(jsonify({'error': str(err)}), 400)


@application.route('/queue/members/<member_id>', methods=['PATCH'])
@auth.login_required
def queue_update_member(member_id):
    try:
        update_member_task.delay(member_id=member_id)
        return make_response(jsonify({'success': "Update in queue"}), 200)
    except Exception as err:
        return make_response(jsonify({'error': str(err)}), 400)


@application.route('/queue/members/<member_id>', methods=['DELETE'])
@auth.login_required
def queue_delete_member(member_id):
    try:
        delete_member_task.delay(member_id)
        return make_response(jsonify({'success': "Delete in queue"}), 200)
    except Exception as err:
        return make_response(jsonify({'error': str(err)}), 400)


@application.route('/queue/members/sync', methods=['PUT'])
@auth.login_required
def queue_sync_members():
    try:
        sync_members_task.delay()
        return make_response(jsonify({'success': "Sync in queue"}), 200)
    except Exception as err:
        return make_response(jsonify({'error': str(err)}), 400)
# # </editor-fold>


if __name__ == '__main__':
    application.run()
