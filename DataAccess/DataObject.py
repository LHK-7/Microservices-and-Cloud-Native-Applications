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
    def get_by_email(cls, email):

        sql = "select * from users where email=%s"
        res, data = data_adaptor.run_q(sql=sql, args=(email), fetch=True)
        if data is not None and len(data) > 0:
            result = data[0]
        else:
            result = None

        return result

    @classmethod
    def create_user(cls, user_info):

        result = None

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
        except Exception as e:
            raise DataException()

        return result

    @classmethod
    def update_user(cls, user_info, template):
        result = None
        try:
            sql, args = data_adaptor.create_update(table_name="users", new_values=user_info, template=template)
            res, data = data_adaptor.run_q(sql, args)
            if res != 1:
                result = None
            else:
                result = res
        except Exception as e:
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
            sql = "select password from users where email = " + "'" + user_info + "'"
            res, data = data_adaptor.run_q(sql)
            if res != 1:
                result = None
            else:
                res = data[0].get("password")
        except Exception as e:
            raise DataException()

        return res

    @classmethod
    def validate_password(cls, password):
        try:
            sql = "select password from users where password = " + "'" + password + "'"
            res, data = data_adaptor.run_q(sql)
            if res != 1:
                result = None
            else:
                res = data[0].get("password")
        except Exception as e:
            raise DataException()

        return res


    @classmethod
    def find_postinfo(cls, user_email):
        try:
            sql = "select id,content, image, date from posts where author = " + "'" + user_email + "'"
            res, data = data_adaptor.run_q(sql)
            if res == 0:
                result = json.dumps([], indent=4, sort_keys=True, default=str)
            else:
                result = json.dumps(data, indent=4, sort_keys=True, default=str)
        except Exception as e:
            raise DataException()

        return result

    @classmethod
    def get_comments_of_post(cls, postId):
        try:
            sql = "select * from comments where to_post=%s"
            res, data = data_adaptor.run_q(sql=sql, args=(postId), fetch=True)
            if res == 0:
                result = "there is no comment"
            else:
                result = json.dumps(data, indent=4, sort_keys=True, default=str)
        except Exception as e:
            raise DataException()

        return result

    @classmethod
    def get_comments_of_post(cls, postId):
        try:
            sql = "select * from comments where to_post=%s"
            res, data = data_adaptor.run_q(sql=sql, args=(postId), fetch=True)
            if res == 0:
                result = "there is no comment"
            else:
                result = json.dumps(data, indent=4, sort_keys=True, default=str)
        except Exception as e:
            raise DataException()

        return result

    @classmethod
    def create_comment(cls, content):

        try:
            sql, args = data_adaptor.create_insert(table_name="comments", row=content)
            res, data = data_adaptor.run_q(sql, args)
            if res != 1:
                result = json.dumps([], indent=4, sort_keys=True, default=str)
            else:
                result = json.dumps(data, indent=4, sort_keys=True, default=str)
        except Exception as e:
            raise DataException()

        return result