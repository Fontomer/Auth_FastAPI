from pydantic import BaseModel, Field
from typing import Annotated


class User(BaseModel):
    username: Annotated[
        str, Field(
            ..., title='Type your username', min_length=3, max_length=20
            )
        ]
    password: Annotated[
        str, Field(
            ..., title='Type your password', min_length=6, max_length=30
        )
    ]

class UserCreate(User): #схема того какие данные может отправлять пользователь
    pass

class UserLogin(User):
    pass

class UserDel(BaseModel):
    id: int