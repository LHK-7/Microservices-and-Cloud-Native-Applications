from DataAccess.DataObject import UsersRDB as UsersRDB
from werkzeug.security import generate_password_hash, check_password_hash

class Authentication:

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        print("\n\nSimpleMiddlewareObject: something you want done in every http request")
        return self.app(environ, start_response)

    @classmethod
    def validate(cls, info):
        (user_email, user_password), = info.items()
        res = UsersRDB.validate_info(user_email)
        return check_password_hash(res, user_password)

