import json
import logging
from datetime import datetime
import jwt

from Middleware.authentication import Authentication


class authorization(object):

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        print ("\n\nSimpleMiddlewareObject: something you want done in every http request")
        return self.app(environ, start_response)

    @classmethod
    def authorize(self, url, method, token):
        user = url.split('/')[-1].replace("%40", "@")
        validations = jwt.decode(token, 'secret', algorithms=['HS256'])
        password = validations['password']
        # print()
        tmp = {user: password}
        # print(tmp)
        res = Authentication.validate(tmp)

        if method == "GET":
            return True
        if method == "POST":
            return False

        if method == "DELETE":
            if user == 'admin':
                return True
            else:
                return False

        if not res:
            return False

        return True
