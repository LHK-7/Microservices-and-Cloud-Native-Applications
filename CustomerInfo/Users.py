import json
from abc import ABC, abstractmethod
from Context import Context
from DataAccess.DataObject import UsersRDB as UsersRDB
from Middleware.notification import publish_it


# The base classes would not be IN the project. They would be in a separate included package.
# They would also do some things.


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
    def get_user_by_email(cls, email):
        result = UsersRDB.get_user_by_email(email)
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
    def get_profile_by_email(cls, email):
        result = UsersRDB.get_profile_by_userid(email)
        profile = {}
        if len(result) > 0:
            profile["profile_id"] = result[0]["profile_id"]
            profile["user_id"] = result[0]["user_id"]
            profile["profile_entries"] = UsersService.filter_profile(result)
        return profile

    @classmethod
    def get_profile_by_id(cls, pid):
        result = UsersRDB.get_profile_by_id(pid)
        profile = {}
        if len(result) > 0:
            profile["profile_id"] = result[0]["profile_id"]
            profile["user_id"] = result[0]["user_id"]
            profile["profile_entries"] = UsersService.filter_profile(result)
        return profile

    @classmethod
    def update_profile_by_id(cls, pid, profile):
        new_values = []
        uid, entries = profile['user_id'], profile['profile_entries']

        if entries:
            for entry in entries:
                new_values.append({
                    "profile_id": pid,
                    "user_id": uid,
                    "element_type": entry["type"],
                    "element_subtype": entry["subtype"],
                    "element_value": entry["value"],
                })

        result = UsersRDB.update_profile_by_id(pid, new_values)
        return result

    @classmethod
    def delete_profile_by_id(cls, pid):
        result = UsersRDB.delete_profile_by_id(pid)
        return result

    @staticmethod
    def filter_profile(entries):
        output = []
        for entry in entries:
            output.append({k: entry[k] for k in ["type", "subtype", "value"]})
        return output

    @classmethod
    def activate_user(cls, user_info):
        v = user_info.get('email', None)
        res = UsersRDB.get_user_by_email(v)
        if res is None:
            raise ServiceException(ServiceException.bad_data,
                                   "Email not in database: " + v)
        template = {'email': v}
        result = UsersRDB.update_user(user_info=user_info, template=template)
        return result

    @classmethod
    def update_user(cls, data):
        v = data["email"]
        res = UsersRDB.get_user_by_email(v)
        if res is None:
            raise ServiceException(ServiceException.bad_data,
                                   "Email not in database: " + v)
        # server_etag = to_etag(res)
        # if client_etag == server_etag:
        template = {"email": v}
        result = UsersRDB.update_user(user_info=data, template=template)
        # else:
        result = "No action done due to Etag mismatch. This is usually because your info was modified during " \
                 "your updating. "
        return result

    @classmethod
    def delete_user(cls, user_info):
        result = UsersRDB.delete_user(user_info)
        return result
