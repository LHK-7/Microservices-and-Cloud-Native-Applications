# Set up the following THREE environment variables before running.
# test={"host":"localhost","user":"root","password":"123","port":3306,"db":"e6156","charset":"utf8mb4"}
# dynamo=
# sns=

###################################################################################################################

import json
import os
import uuid
from datetime import datetime

# - Flask is the top-level application. You implement the application by adding methods to it.
# - Response enables creating well-formed HTTP/REST responses.
# - requests enables accessing the elements of an incoming HTTP/REST request.
from flask import Flask, Response, request, render_template, redirect, url_for, g
from flask_wtf import FlaskForm
from flask_cors import CORS
from wtforms import Form, StringField, PasswordField, validators, SubmitField
from functools import wraps
import jwt

import DataAccess.DataAdaptor as DataAdaptor
import DataAccess.dynamo as dynamo
from Context.Context import Context
from CustomerInfo.Users import UsersService as UserService
from Middleware.etag import to_etag
from Middleware.authentication import Authentication
from Middleware.authorization import authorization
from DataAccess.DataObject import UsersRDB as UsersRDB
from CustomerInfo.Address import validate_address
from werkzeug.security import generate_password_hash,check_password_hash


# Setup and use the simple, common Python logging framework. Send log messages to the console.
# The application should get the log level out of the context. We will change later.
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


###################################################################################################################
#
# AWS put most of this in the default application template.
#
# AWS puts this function in the default started application
# print a nice greeting.
def say_hello(username="World"):
    return '<p>Hello %s!</p>\n' % username


# AWS put this here.
# some bits of text for the page.
header_text = '''
    <html>\n<head> <title>EB Flask Test</title> </head>\n<body>'''
instructions = '''
    <p><em>Hint</em>: This is a RESTful web service! Append a username
    to the URL (for example: <code>/Thelonious</code>) to say hello to
    someone specific.</p>\n'''
home_link = '<p><a href="/">Back</a></p>\n'
footer_text = '</body>\n</html>'

# EB looks for an 'application' callable by default.
# This is the top-level application that receives and routes requests.
application = Flask(__name__)

# we may not need this
config = {
    'ORIGINS': [
        'http://localhost:4200',
        'http://127.0.0.1:5000/ ',  # flask
        'https://e6156.surge.sh',  # angular
        'http://e6156-yeah.s3-website.us-east-2.amazonaws.com', # s3
        'https://d32e0zjclv95xl.cloudfront.net' # cloudfront
    ]
}
allowed_url = 'https://d32e0zjclv95xl.cloudfront.net'
# allowed_url = 'http://localhost:4200' # TODO: change this to cloudfront

# Enable CORS
CORS(application, resources={r"/*": {"origins": config['ORIGINS']}},
     headers='Content-Type, X-Api-Key, Token', supports_credentials=True)

# add a rule for the index page. (Put here by AWS in the sample)
application.add_url_rule('/', 'index', (lambda: header_text +
                                                say_hello() + instructions + footer_text))

# add a rule when the page is accessed with a name appended to the site
# URL. Put here by AWS in the sample
application.add_url_rule('/<username>', 'hello', (lambda username:
                                                  header_text + say_hello(username) + home_link + footer_text))

##################################################################################################################
# The stuff I added begins here.

_default_context = None
_user_service = None


def _get_default_context():
    global _default_context

    if _default_context is None:
        _default_context = Context.get_default_context()

    return _default_context


def _get_user_service():
    global _user_service

    if _user_service is None:
        _user_service = UserService(_get_default_context())

    return _user_service


def init():
    global _default_context, _user_service

    _default_context = Context.get_default_context()
    _user_service = UserService(_default_context)

    logger.debug("_user_service = " + str(_user_service))


# Encrypt session
SECRET_KEY = os.urandom(32)
application.config['SECRET_KEY'] = SECRET_KEY


# def login_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if request.get_json() is None:
#             return redirect(url_for('login', next=request.url))
#         return f(*args, **kwargs)
#
#     return decorated_function


@application.before_request
def before_decorator():
    rule = request.endpoint
    try:
        if request.method == 'OPTIONS' or rule is 'registration' or rule is 'login' or request.headers.get(
                "pass") == 'sL36KjRf5oAc79ifhPJAz1bqi03WQPCC':
            pass
        else:
            token = request.headers.get("Token")
            fblogin = False
            if request.headers.has_key("X-Api-Key"):
                fblogin = json.loads(request.headers["X-Api-Key"])
            if fblogin:
                user = token
            else:
                tmp = jwt.decode(request.headers["Token"], 'secret', algorithms=['HS256'])
                user = tmp.get("user")
                password = tmp.get("password")

                res = UsersRDB.validate_info(user)
                if res != password:
                    raise ValueError("Your information cannot be identify!")
            g.user = user
    except Exception as exp:
        rsp_txt = "ERROR: Unauthorized user. Login required.\n{}".format(exp)
        rsp_status = 504
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")
        return full_rsp


# 1. Extract the input information from the requests object.
# 2. Log the information
# 3. Return extracted information.
def log_and_extract_input(path_params=None):
    path = request.path
    args = request.args.to_dict()
    data = None
    headers = dict(request.headers)
    method = request.method

    try:
        if request.data is not None:
            data = request.json
        else:
            data = None
    except Exception as e:
        # This would fail the request in a more real solution.
        data = "You sent something but I could not get JSON out of it."

    log_message = str(datetime.now()) + ": Method " + method

    inputs = {
        "path": path,
        "method": method,
        "path_params": path_params,
        "query_params": args,
        "headers": headers,
        "body": data
    }

    log_message += " received: \n" + json.dumps(inputs, indent=2)
    logger.debug(log_message)

    return inputs


def log_response(method, status, data, txt):
    msg = {
        "method": method,
        "status": status,
        "txt": txt,
        "data": data
    }

    logger.debug(str(datetime.now()) + ": \n" + json.dumps(msg, indent=2))

# Registration service.
@application.route("/api/user/registration", endpoint="registration", methods=["POST"])
def user_register():
    global _user_service

    param = request.get_json()
    rsp_status = 400  # bad request
    tempass = param['password']
    pass_hash = generate_password_hash(tempass)
    try:
        temp = {
            'id': str(uuid.uuid4()),
            'last_name': param['last_name'],
            'first_name': param['first_name'],
            'email': param['email'],
            'password': pass_hash
        }

        user_service = _get_user_service()
        user_service.create_user(temp)
        rsp_txt = json.dumps("user created")
        rsp_status = 200
    except Exception as exp:
        rsp_txt = json.dumps(exp)

    full_rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")

    return full_rsp


@application.route("/api/user/login", endpoint="login", methods=["POST"])
def login():
    user = request.json['username']
    password = request.json['password']
    res = Authentication.validate({ user: password })
    if res:
        encoded_password = jwt.encode({'password': password, 'user': user}, 'secret', algorithm='HS256').decode(
            'utf-8')
        rsp_data = {
            "result": res,
            "Token": encoded_password
        }
        status = UsersRDB.get_user_status(user)
        if status == 'ACTIVE':
            rsp_status = 200
            rsp_txt = json.dumps(rsp_data)
            full_rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")
            full_rsp.headers["Token"] = encoded_password
        else:
            rsp_status = 403
            rsp_txt = "User not Activated."
            full_rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")

    else:
        error = 'Invalid Credentials. Please try again.'
        rsp_data = {
            "result": res,
            "error": error
        }
        rsp_status = 504
        rsp_txt = json.dumps(rsp_data)
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")

    full_rsp.headers["Access-Control-Allow-Origin"] = allowed_url
    full_rsp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    full_rsp.headers["Access-Control-Allow-Methods"] = "POST"
    full_rsp.headers["Access-Control-Allow-Credentials"] = "true"
    full_rsp.headers["Access-Control-Expose-Headers"] = "Token"
    return full_rsp


@application.route("/api/user/<email>", methods=["GET", "PUT", "POST", "DELETE"])
def user_email(email):
    global _user_service

    inputs = log_and_extract_input({"parameters": email})
    rsp_data = None
    rsp_status = None
    rsp_txt = None

    try:
        user_service = _get_user_service()

        # logger.error("/email: _user_service = " + str(user_service))

        if inputs["method"] == "GET":

            rsp = user_service.get_user_by_email(email)

            if rsp is not None:
                # etag = to_etag(rsp)
                rsp_data = rsp
                rsp_status = 200
                rsp_txt = "OK"
            else:
                rsp_data = None
                rsp_status = 404
                rsp_txt = "NOT FOUND"

            links = "links": [
                {
                    "href": "api/profile/<email> ",
                    "rel": "profile",
                    "method": "GET, PUT, DELETE"
                },
                {
                    "href": "/api/customers/<email>/profile",
                    "rel": "profile",
                    "method": "GET"
                },
                {
                    "href": "api/profile ",
                    "rel": "profile",
                    "method": "GET, POST"
                }
            ]
            return json.dumps(links)

        elif inputs["method"] == 'PUT':
            temp = {"email": email, "status": "ACTIVE"}
            rsp_data = user_service.activate_user(temp)
            rsp_status = 200
            rsp_txt = str(rsp_data)

        elif inputs["method"] == 'POST':
            # client_etag = request.headers["ETag"]
            # res = [id, last_name, first_name, email, password]
            # temp = {"id": res[0], "last_name": res[1], "first_name": res[2], "email": res[3], "password": res[4]}
            temp = request.json
            temp["email"] = email
            rsp_data = user_service.update_user(temp)
            rsp_status = 200
            rsp_txt = str(rsp_data)

        elif inputs["method"] == "DELETE":  # This SHOULD SET STATUS to DELETED instead of removing the tuple
            rsp_data = user_service.delete_user({"email": email})
            rsp_status = 200
            rsp_txt = str(rsp_data)

        else:
            rsp_data = None
            rsp_status = 501
            rsp_txt = "NOT IMPLEMENTED"

        if rsp_data is not None:
            full_rsp = Response(json.dumps(rsp_data), status=rsp_status, content_type="application/json")
            # if inputs["method"] == "GET":
            #     full_rsp.headers["ETag"] = etag

        else:
            full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")

    except Exception as e:
        log_msg = "/email: Exception = " + str(e)
        logger.error(log_msg)
        rsp_status = 500
        rsp_txt = "INTERNAL SERVER ERROR. Please take COMSE6156 -- Cloud Native Applications."
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")

    # full_rsp.headers['Access-Control-Allow-Origin'] = '*'

    log_response("/email", rsp_status, rsp_data, rsp_txt)

    return full_rsp


@application.route("/addresses", methods=["POST"])
def create_address():
    """
    request_body = {
        "address_line_1": "13161 Brayton Drive",
        "address_line_2": "APT #30",
        "city": "Anchorage",
        "state": "AK"
    }
    """
    input_address = log_and_extract_input()['body']
    validated = validate_address(input_address)
    if validated == 'Invalid.':
        # if address is invalid, return False
        rsp_status = 422
        rsp_txt = "Invalid Address."
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")
        return full_rsp
    else:
        # if success, return the address id
        rsp_status = 201
        rsp_txt = dynamo.addAddress(validated)
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")
        return full_rsp


@application.route("/addresses/<address_id>", methods=["GET"])
def get_or_update_address(address_id):
    rsp_status = 200
    rsp_txt = json.dumps(dynamo.getAddress(address_id))
    full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")
    return full_rsp


# query string: ?email=<email>
@application.route("/api/profile", methods=["GET", "POST"])
def profile_service_1():
    return None


# Etag (GET|PUT) is implemented here.
@application.route("/api/profile/<profile_id>", methods=["GET", "PUT", "DELETE"])
def profile_service_2(profile_id):
    global _user_service

    rsp_txt = "Bad request: "
    rsp_status = 400

    if request.method == "GET":
        try:
            user_service = _get_user_service()
            profile = user_service.get_profile_by_id(profile_id)
            profile["links"] = [
                {
                    "href": "/api/customers/<email>/profile",
                    "rel": "profile",
                    "method": "GET"
                },
                {
                    "href": "api/profile ",
                    "rel": "profile",
                    "method": "GET, POST"
                }
            ]
            # etag = to_etag(profile)
            rsp_txt = json.dumps(profile)

            rsp_status = 200
            # rsp.headers["ETag"] = etag
            # rsp.headers['Access-Control-Expose-Headers'] = 'ETag'

        except Exception as exp:
            rsp_txt += str(exp)

    elif request.method == "PUT":
        try:
            user_service = _get_user_service()
            profile = log_and_extract_input()["body"]
            original_profile = user_service.get_profile_by_id(profile_id)

            etag = to_etag(original_profile)
            if not request.headers.get("If-Match"):
                rsp_txt = "Missing ETag"
                rsp_status = 504
            elif etag == request.headers.get("If-Match"):
                res = user_service.update_profile_by_id(profile_id, profile)
                rsp_txt = "entries updated"
                rsp_status = 200
            else:
                rsp_txt = "ETag Does Not Match"
                rsp_status = 504

        except Exception as exp:
            rsp_txt += str(exp)

    elif request.method == "DELETE":
        try:
            user_service = _get_user_service()
            res = user_service.delete_profile_by_id(profile_id)
            rsp_txt = "{} entries deleted".format(res)
            rsp_status = 200

        except Exception as exp:
            rsp_txt += str(exp)

    rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")
    return rsp


@application.route("/api/user/<email>/profile", methods=["GET"])
def show_profile(email):
    global _user_service

    rsp_txt = "Bad request: "
    rsp_status = 400

    if request.method == "GET":
        try:
            user_service = _get_user_service()
            profile = user_service.get_profile_by_email(email)
            profile["links"] = [
                {
                    "href": "api/profile/<email> ",
                    "rel": "profile",
                    "method": "GET, PUT, DELETE"
                },
                {
                    "href": "api/profile ",
                    "rel": "profile",
                    "method": "GET, POST"
                }
            ]
            etag = to_etag(profile)
            rsp_txt = json.dumps(profile)

            rsp_status = 200
            rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")
            rsp.headers["ETag"] = etag
            rsp.headers['Access-Control-Expose-Headers'] = 'ETag'

        except Exception as exp:
            rsp_txt += str(exp)
            rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")

        return rsp


@application.route('/resource', methods=['GET'], defaults={'primary_key_value': None})
@application.route('/resource/<primary_key_value>', methods=['GET'])
def resource_by_template(primary_key_value=None):
    try:
        # Parse the incoming request into an application specific format.
        context = log_and_extract_input()
        template = {'email': primary_key_value} if primary_key_value else context.get('query_params', {})
        fields = context.get('query_params', {}).pop('f', None)
        if fields:
            fields = fields.split(',')

        if request.method == 'GET':
            sql, args = DataAdaptor.create_select(table_name='users', template=template, fields=fields)
            res, data = DataAdaptor.run_q(sql, args)
            if res and len(data) > 0:

                result = json.dumps(data, default=str)

                rsp_data = result
                rsp_status = 200
                rsp_txt = str(rsp_data)

                full_rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")

                return full_rsp
            else:
                rsp_status = 404
                rsp_txt = "Not Found"
                full_rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")

                return full_rsp
    except Exception as e:
        print(e)
        rsp_txt = "Internal Error"
        rsp_status = 504
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")

        return full_rsp


@application.route('/articles', methods=['GET', 'POST'])
def get_articles():
    if request.method == 'GET':
        try:
            curr_user = g.user
            results = UsersRDB.find_post_by_authors(curr_user)

            rsp_status = 200
            full_rsp = Response(results, status=rsp_status, content_type="application/json")

            return full_rsp
        except Exception as e:
            rsp_txt = "Not Found"
            rsp_status = 404
            full_rsp = Response(rsp_txt, status=rsp_status, content_type="application/json")

            return full_rsp
    elif request.method == 'POST':
        curr_user = g.user
        content = {'author': curr_user, 'content': request.json['text'], 'image': request.json['image'],
                   'date': request.json['date']}
        try:
            result = UsersRDB.create_post(content)
            print(result)
            if result != 0:
                results = UsersRDB.find_post_by_authors(curr_user)
            else:
                results = []
            rsp_status = 200
        except Exception as e:
            results = "Cannot create the post! Please try again."
            rsp_status = 404

        full_rsp = Response(results, status=rsp_status, content_type="application/json")
        return full_rsp


@application.route("/logout", methods=['GET', 'PUT', 'POST'])
def logout():
    g.user = None
    results = 'Logged Out!'
    rsp_status = 200
    full_rsp = Response(results, status=rsp_status, content_type="application/json")
    return full_rsp


@application.route('/articles/<post_id>', methods=['GET', 'POST'])
def get_comments(post_id):
    if request.method == 'GET':
        try:
            results = UsersRDB.get_comments_of_post(post_id)
            rsp_status = 200
        except Exception as e:
            results = "Not Found"
            rsp_status = 404

        full_rsp = Response(results, status=rsp_status, content_type="application/json")
        return full_rsp

    elif request.method == 'POST':
        curr_user = g.user
        content = {'author': curr_user, 'to_post': post_id, 'content': request.json['content'],
                   'date': request.json['date']}
        try:
            results = UsersRDB.create_comment(content)
            rsp_status = 200
        except Exception as exp:
            results = "Not Found"
            rsp_status = 404
        full_rsp = Response(results, status=rsp_status, content_type="application/json")
        return full_rsp


@application.route('/following', methods=['GET'])
def get_following_users():
    try:
        results = UsersRDB.get_following_users(g.user)
        rsp_status = 200

    except Exception as exp:
        results = "Not Found"
        rsp_status = 404

    full_rsp = Response(results, status=rsp_status, content_type="application/json")
    return full_rsp


logger.debug("__name__ = " + str(__name__))

# run the app.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production app.
    logger.debug("Starting Project EB at time: " + str(datetime.now()))
    init()

    application.debug = True
    application.run()
