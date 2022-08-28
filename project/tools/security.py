import base64
import hashlib
import calendar
import datetime

import jwt
from flask import current_app, request
from flask_restx import abort

#from project.container import user_service
from project.services.users_service import UsersService


def __generate_password_digest(password: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=current_app.config["PWD_HASH_SALT"],
        iterations=current_app.config["PWD_HASH_ITERATIONS"],
    )


def generate_password_hash(password: str) -> str:
    return base64.b64encode(__generate_password_digest(password)).decode('utf-8')


def compare_password(password_hash, other_password):
    """

    :param password_hash:  пароль из БД
    :param other_password: пароль который прислал пользователь
    :return:
    """
    return password_hash == generate_password_hash(other_password)


def generate_token(email, password, is_refresh=False):
    """
    Генерация новых токенов, а так же пары токенов при окончании времени Access токена
    :param email:
    :param password:
    :param is_refresh:
    :return:
    """

    user = UsersService.get_user_by_email(email)

    if user is None:
        raise abort(404)

    if not is_refresh:
        if not compare_password(user.password, password):
            abort(400)

    data = {
        "email": user.email
    }

    min15 = datetime.datetime.utcnow() + datetime.timedelta(minutes=current_app.config['TOKEN_EXPIRE_MINUTES'])
    data["exp"] = calendar.timegm(min15.timetuple())
    access_token = jwt.encode(data, key=current_app.config['SECRET_KEY'],
                              algorithm=current_app.config['ALGORITHM'])

    days130 = datetime.datetime.utcnow() + datetime.timedelta(days=current_app.config['TOKEN_EXPIRE_DAYS'])
    data["exp"] = calendar.timegm(days130.timetuple())
    refresh_token = jwt.encode(data, key=current_app.config['SECRET_KEY'],
                               algorithm=current_app.config['ALGORITHM'])

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }


def update_token(refresh_token):
    data = jwt.decode(refresh_token, key=current_app.config['SECRET_KEY'],
                      algorithms=current_app.config['ALGORITHM'])

    email = data.get('email')
    password = data.get('password')

    return generate_token(email=email, password=password, is_refresh=True)


def get_data_by_token(refresh_token):
    data = jwt.decode(refresh_token, key=current_app.config['SECRET_KEY'],
                      algorithms=current_app.config['ALGORITHM'])

    return data


def auth_required(func):
    """
    Декоратор проверки авторизации
    :param func:
    :return:
    """

    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split("Bearer ")[-1]
        try:
            jwt.decode(token, key=current_app.config['SECRET_KEY'],
                       algorithm=current_app.config['ALGORITHM'])
        except Exception as e:
            print("JWT Decode Exception", e)
            abort(401)
        return func(*args, **kwargs)

    return wrapper
