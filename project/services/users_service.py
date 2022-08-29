from typing import Optional

from project.dao import UsersDAO
from project.exceptions import ItemNotFound
from project.models import User
from project.tools.security import generate_token, update_token, get_data_by_token, generate_password_hash


class UsersService:
    def __init__(self, dao: "UsersDAO") -> None:
        self.dao = dao

    def get_item(self, pk: int) -> User:
        if user := self.dao.get_by_id(pk):
            return user
        raise ItemNotFound(f'User with pk={pk} not exists.')

    def get_all(self, page: Optional[int] = None) -> list[User]:
        return self.dao.get_all(page=page)

    def create_user(self, email, password):
        """
        создание пользователz
        :param user_data:
        :return:
        """
        return self.dao.create_user(email=email, password=generate_password_hash(password))

    def get_user_by_email(self, email):
        return self.dao.get_user_by_email(email=email)

    def check(self, email, password):
        user = self.get_user_by_email(email)
        return generate_token(email=email, password=password)

    def update_token(self, refresh_token):
        return update_token(refresh_token=refresh_token)

    def get_user_by_token(self, token):
        data = get_data_by_token(token)
        return self.get_user_by_email(data.get('email'))

    def update_user(self, data, token):
        user = get_data_by_token(token)
        if user:
            self.dao.update_user(data=data, email=user.get('email'))

            return self.get_user_by_email(user.get('email'))

    def update_password(self, data, token):
        user = get_data_by_token(token)
        if data:
            self.dao.update_user(
                data={
                    'password': generate_password_hash(data.get('password_2'))
                },
                email=user.get('email')
            )

            return self.get_user_by_email(data.get('email'))

