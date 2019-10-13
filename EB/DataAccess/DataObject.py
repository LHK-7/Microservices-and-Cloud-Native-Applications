import DataAccess.DataAdaptor as data_adaptor
import pymysql.err

from abc import ABC, abstractmethod


class DataException(Exception):

    unknown_error   =   1001
    duplicate_key   =   1002

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

        sql = "select * from e6156.users where email=%s"
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
    def update_user(cls, user_info,template):
        result = None
        try:
            sql, args = data_adaptor.create_update(table_name="users", new_values=user_info,template=template)
            res, data = data_adaptor.run_q(sql, args)
            if res != 1:
                result = None
            else:
                result = user_info['id']
        except Exception as e:
            raise DataException()

        return result
