# ENV VARS: test={"host":"localhost","user":"root","password":"123","port":3306,"db":"e6156","charset":"utf8mb4"}
# {"host":"database-6156.cbl6qjbnc3gz.us-east-1.rds.amazonaws.com","user": "admin","password": "woshishabi","db": "innodb","charset":"utf8mb4","port":3306}
# Table Name MUST be "users"

# Import functions and objects the microservice needs.
# - Flask is the top-level application. You implement the application by adding methods to it.
# - Response enables creating well-formed HTTP/REST responses.
# - requests enables accessing the elements of an incoming HTTP/REST request.

import uuid

from flask import Flask, Response, request, render_template
from werkzeug.utils import redirect
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from datetime import datetime
import json

from EB.CustomerInfo.Users import UsersService as UserService, to_etag
from EB.Context.Context import Context

# Setup and use the simple, common Python logging framework. Send log messages to the console.
# The application should get the log level out of the context. We will change later.
#
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


# 1. Extract the input information from the requests object.
# 2. Log the information
# 3. Return extracted information.
#
def log_and_extract_input(method, path_params=None):
    path = request.path
    args = dict(request.args)
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


# This function performs a basic health check. We will flesh this out.
# @application.route("/health", methods=["GET"])
# def health_check():
#     rsp_data = {"status": "healthy", "time": str(datetime.now())}
#     rsp_str = json.dumps(rsp_data)
#     rsp = Response(rsp_str, status=200, content_type="application/json")
#     return rsp


# # Demo. Return the received inputs.
# @application.route("/demo/<parameter>", methods=["GET", "POST"])
# def demo(parameter):
#     inputs = log_and_extract_input(demo, {"parameter": parameter})
#
#     msg = {
#         "/demo received the following inputs": inputs
#     }
#
#     rsp = Response(json.dumps(msg), status=200, content_type="application/json")
#     return rsp


# # REDIRECT
# @application.route("/api/redirect", methods=["GET"])
# def redir():
#     return redirect("http://www.example.com", code=302)


class RegisterForm(Form):
    last_name = StringField('Last Name', [validators.Length(min=1, max=50)])
    first_name = StringField('First Name', [validators.Length(min=1, max=50)])
    email = StringField('Email', [validators.length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired()
    ])


@application.route("/api/user/registeration", methods=["GET", "POST"])
def register_user():
    global _user_service

    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        last_name = form.last_name.data
        first_name = form.first_name.data
        email = form.email.data
        password = form.password.data
        id = str(uuid.uuid4())

        res = [id, last_name, first_name, email, password]
        temp = {'id': res[0], 'last_name': res[1], 'first_name': res[2], 'email': res[3], 'password': res[4]}

        print(res)
        print(temp)

        user_service = _get_user_service()
        rsp = user_service.create_user(temp)
        return render_template('register.html', form=form)

    return render_template('register.html', form=form)


@application.route("/api/user/<email>", methods=["GET", "PUT", "POST", "DELETE"])
def user_email(email):
    global _user_service

    inputs = log_and_extract_input(demo, {"parameters": email})
    rsp_data = None
    rsp_status = None
    rsp_txt = None

    try:
        user_service = _get_user_service()

        logger.error("/email: _user_service = " + str(user_service))

        if inputs["method"] == "GET":

            rsp = user_service.get_by_email(email)

            if rsp is not None:
                etag = to_etag(rsp)
                rsp_data = rsp
                rsp_status = 200
                rsp_txt = "OK"
            else:
                rsp_data = None
                rsp_status = 404
                rsp_txt = "NOT FOUND"

        elif request.method == 'PUT':
            temp = {"email": email, "status": "ACTIVE"}
            rsp_data = user_service.activate_user(temp)
            rsp_status = 200
            rsp_txt = str(rsp_data)

        elif request.method == 'POST':
            client_etag = request.headers["ETag"]

            # form = RegisterForm(request.form)
            # if form.validate():
            #     last_name = form.last_name.data
            #     first_name = form.first_name.data
            #     email = form.email.data
            #     password = form.password.data
            #     id = str(uuid.uuid4())
            #
            #     res = [id, last_name, first_name, email, password]
            #     temp = {"id": res[0], "last_name": res[1], "first_name": res[2], "email": res[3], "password": res[4]}
            temp = request.json
            temp["email"] = email
            rsp_data = user_service.update_user(temp, client_etag)
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
            if inputs["method"] == "GET":
                full_rsp.headers["ETag"] = etag
        else:
            full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")

    except Exception as e:
        log_msg = "/email: Exception = " + str(e)
        logger.error(log_msg)
        rsp_status = 500
        rsp_txt = "INTERNAL SERVER ERROR. Please take COMSE6156 -- Cloud Native Applications."
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")

    log_response("/email", rsp_status, rsp_data, rsp_txt)

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
