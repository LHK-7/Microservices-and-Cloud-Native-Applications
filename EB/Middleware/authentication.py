import json

from EB.DataAccess.DataObject import UsersRDB as UsersRDB

class authentication():

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        print ("\n\nSimpleMiddlewareObject: something you want done in every http request")
        return self.app(environ, start_response)

    @classmethod
    def validate(self, info):
        for user, password in info.items():
            user_email = user
            user_password = password

        res = UsersRDB.validate_info(user_email)
        if res == user_password:
            return True
        else:
            return False