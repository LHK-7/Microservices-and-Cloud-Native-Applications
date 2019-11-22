import json
import logging
from datetime import datetime

import jwt
from flask import Flask, Response, request
from werkzeug.wrappers import Response as wResponse
from functools import wraps
from flask import g, request, redirect, url_for
from EB.Middleware.authentication import authentication


class authorization(object):

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        print ("\n\nSimpleMiddlewareObject: something you want done in every http request")
        return self.app(environ, start_response)

    @classmethod
    def authorize(self,url, method, token):
        user = url.split('/')[-1].replace("%40", "@")
        validations = jwt.decode(token, 'secret', algorithms=['HS256'])
        password = validations['password']
        print()
        tmp = {user: password}
        print(tmp)
        res = authentication.validate(tmp)

        if method == "GET":
            return True
        if method == "CREATE":
            return False

        if method == "DELETE":
            if user == 'admin':
                return True
            else:
                return False

        if not res:
            return False

        return True
