# ENV VARS
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
from flask import Flask, Response, request, render_template, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import Form, StringField, PasswordField, validators, SubmitField
from smartystreets_python_sdk import StaticCredentials, exceptions, ClientBuilder
from smartystreets_python_sdk.us_street import Lookup

import DataAccess.DataAdaptor as DataAdaptor
import DataAccess.dynamo as dynamo
from Context.Context import Context
from CustomerInfo.Users import UsersService as UserService, to_etag
import jwt

from Middleware.authentication import authentication
from Middleware.authorization import authorization
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

from functools import wraps


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.get_json() is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@application.before_request
def before_decorator():
    rule = request.endpoint
    print("Endpoint", rule)
    if rule is not 'login':
        if request.get_json() is not None:
            print("authentication",request.get_json().get('password'))
            if not authentication.passwordValidate(request.get_json().get('password')):
                raise ValueError("your information cannot be identify")



@application.after_request
def after_decorator(rsp):
    print("... In after decorator ...")
    return rsp


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


# This function performs a basic health check. We will flesh this out.
# @application.route("/health", methods=["GET"])
# def health_check():
#     rsp_data = {"status": "healthy", "time": str(datetime.now())}
#     rsp_str = json.dumps(rsp_data)
#     rsp = Response(rsp_str, status=200, content_type="application/json")
#     return rsp


# Demo. Return the received inputs.
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
def user_register():
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

        # print(res)
        # print(temp)

        user_service = _get_user_service()
        rsp = user_service.create_user(temp)
        return render_template('register.html', form=form)

    return render_template('register.html', form=form)

@application.route("/api/user/login", endpoint="login", methods=["GET","POST","PUT"])
def login():
    error = None
    if request.method == 'POST':
        user = request.form['username']
        password = request.form['password']
        tmp = {user:password}
        res = authentication.validate(tmp)
        if res:
            encoded_password = jwt.encode({'password':password}, 'secret', algorithm='HS256').decode('utf-8')
            print("encoded_password",encoded_password)
            return render_template('Home.html', encoded_password=encoded_password)
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)


@application.route("/api/user/<email>", methods=["GET", "PUT", "DELETE"])
#@login_required
def user_email(email):
    global _user_service
    request_url = request.url

    inputs = log_and_extract_input(demo, {"parameters": email})
    rsp_data = None
    rsp_status = None
    rsp_txt = None

    try:
        user_service = _get_user_service()


        logger.error("/email: _user_service = " + str(user_service))

        if inputs["method"] == "GET":
            headers = dict(request.headers)
            rsp = user_service.get_by_email(email)
            if rsp is not None:
                rsp_data = rsp
                rsp_status = 200
                rsp_txt = "OK"
            else:
                rsp_data = None
                rsp_status = 404
                rsp_txt = "NOT FOUND"

        elif request.method == 'PUT':
            form = registerForm(request.form)

            if form.validate():
                last_name = form.last_name.data
                first_name = form.first_name.data
                email = form.email.data
                password = form.password.data
                id = str(uuid.uuid4())

                res = [id, last_name, first_name, email, password]
                temp = {"id": res[0], "last_name": res[1], "first_name": res[2], "email": res[3], "password": res[4]}

                user_service = _get_user_service()
                rsp = user_service.update_user(temp)

        elif inputs["method"] == "DELETE":
            rsp_data = user_service.delete_user({"email": email})
            rsp_status = 200
            rsp_txt = str(rsp_data)

        else:
            rsp_data = None
            rsp_status = 501
            rsp_txt = "NOT IMPLEMENTED"

        if rsp_data is not None:
            full_rsp = Response(json.dumps(rsp_data), status=rsp_status, content_type="application/json")
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



class Profile1(FlaskForm):
    user = StringField('user')
    Email = StringField('Email')
    Email_sub = StringField('Email_sub')
    Telephone = StringField('Telephone')
    Telephone_sub = StringField('Telephone_sub')
    Address_zipcode = StringField('Address_zipcode')
    Address_State = StringField('Address_State')
    Address_City = StringField('Address_City')
    Address_Street = StringField('Address_Street')
    Address_Street2 = StringField('Address_Street2')
    submit = SubmitField('submit')


class Profile2(FlaskForm):
    Email = StringField('Email')
    Email_sub = StringField('Email_sub')
    Telephone = StringField('Telephone')
    Telephone_sub = StringField('Telephone_sub')
    Address_zipcode = StringField('Address_zipcode')
    Address_State = StringField('Address_State')
    Address_City = StringField('Address_City')
    Address_Street = StringField('Address_Street')
    Address_Street2 = StringField('Address_Street2')
    submit = SubmitField('submit')
    delete = SubmitField('delete')


def ssvalid(d):
    auth_id = "8715bcc7-e3d8-b3b4-ed1f-c7485e2d6002"
    auth_token = "vSQrfCmQIGHIW0WTn9J7"
    credentials = StaticCredentials(auth_id, auth_token)
    client = ClientBuilder(credentials).build_us_street_api_client()
    lookup = Lookup()
    lookup.input_id = "1"  # Optional ID from your system
    lookup.street = d["street"]
    lookup.street2 = d["street2"]
    lookup.secondary = ""
    lookup.city = d["city"]
    lookup.state = d["state"]
    lookup.zipcode = d["zipcode"]
    lookup.candidates = 3
    lookup.match = "Invalid"  # "invalid" is th
    try:
        client.send_lookup(lookup)
    except exceptions.SmartyException as err:
        return err

    result = lookup.result

    # if not result:
    #     return ("No candidates. This means the address is not valid.")

    # first_candidate = result[0]
    # print("ZIP Code: " + first_candidate.components.zipcode)
    # print("County: " + first_candidate.metadata.county_name)
    # print("Latitude: {}".format(first_candidate.metadata.latitude))
    # print("Longitude: {}".format(first_candidate.metadata.longitude))

    # return ("Address is valid.")
    return result


@application.route("/addresses", methods=["POST"])
def postAddressService(address):
    if request.method == "POST":
        return dynamo.addAddress(address)


@application.route("/addresses/<address_id>", methods=["GET"])
def getAddressidService(address_id):
    if request.method == "GET":
        return dynamo.getAddress(address_id)


# query string: ?email=<email>
@application.route("/api/profile", methods=["GET", "POST"])
def profile_1():
    global _user_service

    email = request.args.get("email")

    form = Profile1(request.form)
    Email = form.Email.data
    Email_sub = form.Email_sub.data
    Telephone = form.Telephone.data
    Telephone_sub = form.Telephone_sub.data
    Address_zipcode = form.Address_zipcode.data
    Address_State = form.Address_State.data
    Address_City = form.Address_City.data
    Address_Street = form.Address_Street.data
    Address_Street2 = form.Address_Street2.data
    addressInputTrue = Address_zipcode or Address_State or Address_City or Address_Street or Address_Street2
    address = {"zipcode": Address_zipcode, "state": Address_State, "city": Address_City, "street": Address_Street,
               "street2": Address_Street2}

    if request.method == "GET":
        post = []
        sql = str("SELECT * FROM profile where user = " + "\"" + email + "\"" + ";")
        # print(sql)
        rsp_data = DataAdaptor.run_q(sql)
        # print("\n", rsp_data)
        post.append(rsp_data)
        sql = str("SELECT value FROM profile where user = " + "\"" + email + "\""
                  + "AND type = \"address_id\"" + ";")
        rsp_data = DataAdaptor.run_q(sql)
        if rsp_data[0] > 0:
            address_id = rsp_data[1][0]["value"]
            address = dynamo.getAddress(address_id)
            post.append(address)

        # print(type(post))
        tmp = {
            "links": [
                {
                    "href": "api/profile/<email> ",
                    "rel": "profile",
                    "method": "GET, PUT, DELETE"
                },
                {
                    "href": "/api/customers/<email>/profile",
                    "rel": "profile",
                    "method": "GET"
                }
            ]
        }
        post.append(tmp)
        # post = json.dumps(post)
        return render_template("profile.html", form=form, post=post)

    elif request.method == "POST":
        if addressInputTrue:
            if not ssvalid(address):
                return "No candidates. This means the address is not valid. Please go back and submit again."
            address_id = dynamo.addAddress(address)
            sql = str(
                "INSERT INTO profile (user, value, type, subtype) VALUES ("
                + "\"" + email + "\""
                + ", "
                + "\"" + address_id + "\""
                + ", "
                + "\"address_id\""
                + ", "
                + "\"N.A.\""
                + ");")
            rsp_data = DataAdaptor.run_q(sql)
        if Email:
            sql = str(
                "INSERT INTO profile (user, value, type, subtype) VALUES ("
                + "\"" + email + "\""
                + ", "
                + "\"" + Email + "\""
                + ", "
                + "\"Email\""
                + ", "
                + "\"" + Email_sub + "\""
                + ");")
            rsp_data = DataAdaptor.run_q(sql)
        if Telephone:
            sql = str("INSERT INTO profile (user, value, type, subtype) VALUES ("
                      + "\"" + email + "\""
                      + ", "
                      + "\"" + Telephone + "\""
                      + ", "
                      + "\"Telephone\""
                      + ", "
                      + "\"" + Telephone_sub + "\""
                      + ");")
            rsp_data = DataAdaptor.run_q(sql)
        return redirect(url_for("profile_2", email=email))


@application.route("/api/profile/<email>", methods=["GET", "PUT", "DELETE"])
def profile_2(email):
    global _user_service
    form = Profile2(request.form)

    if request.method == "GET":
        post = []
        sql = str("SELECT * FROM profile where user = " + "\"" + email + "\"" + ";")
        rsp_data = DataAdaptor.run_q(sql)
        # print("\n", rsp_data)
        post.append(rsp_data)
        # sql = str("SELECT address_number FROM profile where user = " + "\"" + email + "\"" + ";")
        # post.append(rsp_data)
        # addnumber = int(data_adaptor.run_q(sql))
        # address_post = getAddress(addnumber)
        # post = rsp + address_post
        tmp = {
            "links": [
                {
                    "href": "api/profile ",
                    "rel": "profile",
                    "method": "GET, POST"
                },
                {
                    "href": "/api/customers/<email>/profile",
                    "rel": "profile",
                    "method": "GET"
                }
            ]
        }
        post.append(tmp)
        post = json.dumps(post)

    elif request.method == "PUT":
        post = "update success"

        Email = form.Email.data
        Email_sub = form.Email_sub.data
        Telephone = form.Telephone.data
        Telephone_sub = form.Telephone_sub.data
        Address_zipcode = form.Address_zipcode.data
        Address_State = form.Address_State.data
        Address_City = form.Address_City.data
        Address_Street = form.Address_Street.data
        Address_Street2 = form.Address_Street2.data
        addressInputTrue = Address_zipcode or Address_State or Address_City or Address_Street or Address_Street2
        address = {"zipcode": Address_zipcode, "state": Address_State, "city": Address_City, "street": Address_Street,
                   "street2": Address_Street2}

        if addressInputTrue:
            if not ssvalid(address):
                return "No candidates. This means the address is not valid. Please go back and submit again."
            sql = str("SELECT value FROM profile WHERE user = " + "\"" + email + "\"" + " and type = \"address_id\"")
            address_id = DataAdaptor.run_q(sql)[1][0]["value"]
            dynamo.updateAddress(address, address_id)
        if Email:
            sql = str(
                "UPDATE profile SET value = " + "\"" + Email + "\"" + " WHERE user = " + "\"" + email + "\"" + " and " + "type = \"email\" and subtype = " + "\"" + Email_sub + "\"")
            rsp_data = DataAdaptor.run_q(sql)
            # print(sql)
        if Telephone:
            sql = str(
                "UPDATE profile SET value = " + "\"" + Telephone + "\"" + " WHERE user = " + "\"" + email + "\"" + " and " + "type = \"telephone\" and subtype = " + "\"" + Telephone_sub + "\"")
            rsp_data = DataAdaptor.run_q(sql)

    elif request.method == "DELETE":
        # print("email = ", email)
        sql = str("DELETE from profile where user = " + "\"" + email + "\"" + ";")
        rsp_data = DataAdaptor.run_q(sql)
        return redirect(url_for("profile_2", email=email))

    return render_template("profile2.html", form=form, post=post)


@application.route("/api/customers/<email>/profile", methods=["GET"])
def show_profile(email):
    global _user_service
    if request.method == "GET":
        post = []
        sql = str("SELECT * FROM profile where user = " + "\"" + email + "\"" + ";")
        rsp_data = DataAdaptor.run_q(sql)
        # print("\n", rsp_data)
        post.append(rsp_data)
        # sql = str("SELECT address_number FROM profile where user = " + "\"" + email + "\"" + ";")
        # post.append(rsp_data)
        # addnumber = int(data_adaptor.run_q(sql))
        # address_post = getAddress(addnumber)
        # post = rsp + address_post
        tmp = {
            "links": [
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
        }
        post.append(tmp)
        post = json.dumps(post)
    return post


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
                return result, 200, {'Content-Type': 'application/json; charset=utf-8'}
            else:
                return "Not found", 404, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        print(e)
        return "Internal error.", 504, {'Content-Type': 'text/plain; charset=utf-8'}


logger.debug("__name__ = " + str(__name__))

# run the app.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production app.
    logger.debug("Starting Project EB at time: " + str(datetime.now()))
    init()

    application.debug = True
    application.run()