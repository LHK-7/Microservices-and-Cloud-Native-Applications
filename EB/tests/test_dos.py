import threading
from threading import current_thread
import DataAccess.DataAdaptor as data_adaptor

threadlocal = threading.local()

# TODO: We should read this information from the environment.
default_connect_info =  {
    "host" :'database-6156.cbl6qjbnc3gz.us-east-1.rds.amazonaws.com',
    "user": 'admin',
    "password": 'woshishabi',
    "db": "database-6156",
    "charset": 'utf8mb4'
}


def t1():

    current_thread().default_connect_info  = default_connect_info
    data_adaptor.get_connection()

t1()
