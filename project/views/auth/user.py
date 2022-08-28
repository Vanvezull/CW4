from flask import request
from flask_restx import Namespace, Resource

from project.container1 import user_service
from project.setup.api.models import user
from project.tools.security import auth_required

api = Namespace('user')

@api.route('/')
class UserView(Resource):
    @api.marshal_with(user, as_list=True, code=200, description='OK')
    @auth_required
    def get(self):
        """
        get user
        :return:
        """
        token = request.headers["Authorization"].split("Bearer ")[-1]
        return user_service.get_user_by_token(token)

    @api.marshal_with(user, as_list=True, code=200, description='OK')
    @auth_required
    def patch(self):
        token = request.headers["Authorization"].split("Bearer ")[-1]
        data = request.json

        return user_service.update_user(data=data, token=token)


@api.route('/password/')
class LoginView(Resource):
    @auth_required
    def put(self):
        """
        update token user
        """
        data = request.json
        token = request.headers["Authorization"].split("Bearer ")[-1]

        return user_service.update_password(data=data, token=token)


