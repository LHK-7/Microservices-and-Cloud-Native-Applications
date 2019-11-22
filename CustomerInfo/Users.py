import json
from abc import ABC, abstractmethod
from EB.Context import Context
from EB.DataAccess.DataObject import UsersRDB as UsersRDB
from Middleware.notification import publish_it
import hashlib

# The base classes would not be IN the project. They would be in a separate included package.
# They would also do some things.

def to_etag(data):
    m = hashlib.sha256()
    m.update(str(data).encode('utf-8'))
    return m.hexdigest()

class ServiceException(Exception):
    unknown_error = 9001
    missing_field = 9002
    bad_data = 9003

    def __init__(self, code=unknown_error, msg="Oh Dear!"):
        self.code = code
        self.msg = msg


class BaseService(ABC):
    missing_field = 2001

    @abstractmethod
    def __init__(self):
        pass


class UsersService(BaseService):
    required_create_fields = ['last_name', 'first_name', 'email', 'password']

    def __init__(self, ctx=None):
        super().__init__()
        if ctx is None:
            ctx = Context.get_default_context()
        self._ctx = ctx

    @classmethod
    def get_by_email(cls, email):

        result = UsersRDB.get_by_email(email)
        return result

    @classmethod
    def create_user(cls, user_info):
        for f in UsersService.required_create_fields:
            v = user_info.get(f, None)
            if v is None:
                raise ServiceException(ServiceException.missing_field,
                                       "Missing field = " + f)
            if f == 'email':
                if v.find('@') == -1:
                    raise ServiceException(ServiceException.bad_data,
                                           "Email looks invalid: " + v)
        result = UsersRDB.create_user(user_info=user_info)

        # Publish a simple message to the specified SNS topic
        email = {'customers_email': user_info.get('email')}
        publish_it(json.dumps(email))

        return result

    @classmethod
    def activate_user(cls, user_info):
        v = user_info.get('email', None)
        res = UsersRDB.get_by_email(v)
        if res is None:
            raise ServiceException(ServiceException.bad_data,
                                   "Email not in database: " + v)
        template = {'email': v}
        result = UsersRDB.update_user(user_info=user_info, template=template)
        return result

    @classmethod
    def update_user(cls, data, client_etag):
        v = data["email"]
        res = UsersRDB.get_by_email(v)
        if res is None:
            raise ServiceException(ServiceException.bad_data,
                                   "Email not in database: " + v)
        server_etag = to_etag(res)
        if client_etag == server_etag:
            template = {"email": v}
            result = UsersRDB.update_user(user_info=data, template=template)
        else:
            result = "No action done due to Etag mismatch. This is usually because your info was modified during " \
                     "your updating. "
        return result

    @classmethod
    def delete_user(cls, user_info):
        result = UsersRDB.delete_user(user_info)
        return result
