import json

from CustomerInfo.Users import UsersService as UserService


def t1():

    r = UserService.get_user_by_email('metus.vitae@nibhAliquamornare.edu')
    print("Result = \n", json.dumps(r, indent=2))


def t2():

    user = {
        "last_name": "Gamgee",
        "first_name": "Sam",
        "email": "sg@shore.gov",
        "password": "cat"
    }

    r = UserService.create_user(user)
    print("Result = ", r)


def test_delete():
    user_info = {"email": "lectus@aliquetsemut.com"}
    r = UserService.delete_user(user_info)


# t1()
# t2()

test_delete()