from DataAccess import DataAdaptor as data_adaptor
from abc import ABC, abstractmethod
import pymysql.err

from datetime import datetime
import json


class DataException(Exception):
    unknown_error = 1001
    duplicate_key = 1002

    def __init__(self, code=unknown_error, msg="Something awful happened."):
        self.code = code
        self.msg = msg


class BaseDataObject(ABC):

    def __init__(self):
        pass

    @classmethod
    @abstractmethod
    def create_instance(cls, data):
        pass


class UsersRDB(BaseDataObject):

    def __init__(self, ctx):
        super().__init__()

        self._ctx = ctx

    @classmethod
    def get_user_by_email(cls, email):
        sql, args = data_adaptor.create_select(table_name="users", template={"email": email}, fields=["*"])
        res, data = data_adaptor.run_q(sql=sql, args=args, fetch=True)
        if data is not None and len(data) > 0:
            result = data[0]
        else:
            result = None
        return result

    @classmethod
    def get_user_status(cls, email):
        sql, args = data_adaptor.create_select(table_name="users", template={"email": email}, fields=["status"])
        res, data = data_adaptor.run_q(sql=sql, args=args, fetch=True)
        return data[0]['status'] if res == 1 else None

    @classmethod
    def get_profile_by_userid(cls, userid):
        sql, args = data_adaptor.create_select(table_name="profile",
                                               template={"user_id": userid},
                                               fields=["user_id", "profile_id", "element_type AS type",
                                                       "element_subtype AS subtype", "element_value AS value"])
        res, data = data_adaptor.run_q(sql, args=args)
        return data if res > 0 else []

    @classmethod
    def get_profile_by_id(cls, pid):
        sql, args = data_adaptor.create_select(table_name="profile",
                                               template={"profile_id": pid},
                                               fields=["user_id", "profile_id", "element_type AS type",
                                                       "element_subtype AS subtype", "element_value AS value"])
        res, data = data_adaptor.run_q(sql, args=args)
        return data

    @classmethod
    def update_profile_by_id(cls, pid, new_values):
        sql = []
        for val in new_values:
            sql.append("""
                INSERT INTO profile (user_id, element_type, element_subtype, profile_id, element_value) 
                VALUES (\"{0}\", \"{1}\", \"{2}\", \"{3}\", \"{4}\") 
                ON DUPLICATE KEY UPDATE 
                user_id = \"{0}\",
                element_type = \"{1}\",
                element_subtype = \"{2}\",
                profile_id = \"{3}\",
                element_value = \"{4}\";
            """.format(val["user_id"], val["element_type"], val["element_subtype"],
                       val["profile_id"], val["element_value"]))
        res, data = data_adaptor.run_q(sql, many=True)

        return res

    @classmethod
    def delete_profile_by_id(cls, pid):
        sql, args = data_adaptor.create_delete(table_name="profile",
                                               template={"profile_id": pid})
        res, data = data_adaptor.run_q(sql, args=args)
        return res

    @classmethod
    def create_user(cls, user_info):
        try:
            sql, args = data_adaptor.create_insert(table_name="users", row=user_info)
            res, data = data_adaptor.run_q(sql, args)
            if res != 1:
                result = None
            else:
                result = user_info['id']
        except pymysql.err.IntegrityError as ie:
            if ie.args[0] == 1062:
                raise (DataException(DataException.duplicate_key))
            else:
                raise DataException()
        except Exception as exp:
            raise DataException()
        return result

    @classmethod
    def update_user(cls, user_info, template):
        try:
            sql, args = data_adaptor.create_update(table_name="users", new_values=user_info, template=template)
            res, data = data_adaptor.run_q(sql, args)
            if res != 1:
                result = None
            else:
                result = res
        except Exception as exp:
            raise DataException()

        return result

    @classmethod
    def delete_user(cls, user_info):
        if not user_info or not user_info["email"]:
            raise ValueError("Error: User must be deleted by a given email.")

        try:
            sql, args = data_adaptor.create_delete(table_name="users", template=user_info)
            res, data = data_adaptor.run_q(sql, args)
            result = res
        except Exception as exp:
            raise exp

        return result

    @classmethod
    def validate_info(cls, user_info):
        try:
            sql, args = data_adaptor.create_select(
                table_name="users", template={"email": user_info}, fields=["password"]
            )
            res, data = data_adaptor.run_q(sql, args=args)
            if res != 1:
                res = None
            else:
                res = data[0].get("password")
        except Exception as exp:
            print("Error: validate_info\n", exp)
            raise DataException()

        return res

    @classmethod
    def get_following_users(cls, curr_user):
        try:
            sql = "SELECT last_name, first_name, email, status, avatar FROM users " + \
                  "WHERE email IN (SELECT followee FROM following WHERE follower = %s)"
            res, data = data_adaptor.run_q(sql, args=[curr_user])
            if res == 0:
                result = json.dumps([])
            else:
                result = json.dumps(data, indent=4, sort_keys=True, default=str)
        except Exception as exp:
            raise DataException()

        return result

    @classmethod
    def find_post_by_authors(cls, curr_user):
        try:
            sql = "SELECT * FROM posts WHERE author IN (SELECT followee FROM following WHERE follower = %s) OR author = %s"
            res, data = data_adaptor.run_q(sql, args=[curr_user, curr_user])
            if res == 0:
                result = json.dumps([])
            else:
                result = json.dumps(data, indent=4, sort_keys=True, default=str)
        except Exception as exp:
            raise DataException()

        return result

    @classmethod
    def create_post(cls, content):
        try:
            sql, args = data_adaptor.create_insert(table_name="posts", row=content)
            res, data = data_adaptor.run_q(sql, args)
        except Exception as e:
            raise DataException()

        return res

    @classmethod
    def get_comments_of_post(cls, post_id):
        try:
            sql, args = data_adaptor.create_select(table_name="comments", fields="*", template={"to_post": post_id})
            res, data = data_adaptor.run_q(sql=sql, args=args, fetch=True)
            if res == 0:
                result = json.dumps([])
            else:
                result = json.dumps(data, indent=4, sort_keys=True, default=str)
        except Exception as exp:
            raise DataException()

        return result

    @classmethod
    def create_comment(cls, content):
        try:
            sql, args = data_adaptor.create_insert(table_name="comments", row=content)
            res, data = data_adaptor.run_q(sql, args)
            if res != 1:
                result = json.dumps([])
            else:
                result = json.dumps(data, indent=4, sort_keys=True, default=str)
        except Exception as exp:
            raise DataException()

        return result
