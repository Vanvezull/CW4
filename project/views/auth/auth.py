from flask import request
from flask_restx import Namespace, Resource

from project.container1 import user_service
from project.setup.api.models import user

api = Namespace('auth')

@api.route('/register')
class RegisterView(Resource):
    @api.marshal_with(user, as_list=True, code=200, description='OK')
    def post(self):
        """
        Create new user
        :return:
        """
        data = request.json

        if data.get('email') and data.get('password'):
            return user_service.create_user(email=data.get('email'), password=data.get('password')), 200
        else:
            return "Что то пошло не так", 401

@api.route('/login/')
class LoginView(Resource):
    def post(self):
        """
        Log in user
        """
        data = request.json

        if data.get('email') and data.get('password'):
            return user_service.check(email=data.get('email'), password=data.get('password')), 200

    def put(self):
        """
        update token user
        """
        data = request.json

        if data.get('access_token') and data.get('refresh_token'):
            return user_service.update_token(access_token=data.get('access_token'), refresh_token=data.get('refresh_token')), 200
        else:
            return "Что то пошло не так", 401

