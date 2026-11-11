from database import Base
from sqlalchemy import Boolean, Column, Integer, String


class User(Base): #вид БД (таблицы, строки, типы данных)
    __tablename__ = 'users' #название таблицы

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_pw = Column(String, nullable=False)
    in_active = Column(Boolean, default=True)

    