import copy
import json
import os


class Context:

    def __init__(self, initial_ctx=None):
        self._context = initial_ctx

    def get_context(self, ctx_name):

        result = self._context.get(ctx_name, None)
        return result

    def set_context(self, ctx_name, ctx):

        self._context[ctx_name] = copy.deepcopy(ctx)

    @classmethod
    def get_default_context(cls):

        db_connect_info = os.environ['test']
        db_connect_info = json.loads(db_connect_info)

        ctx = { "db_connect_info": db_connect_info }

        result = Context(ctx)
        return result
