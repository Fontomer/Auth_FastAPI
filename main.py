from fastapi import FastAPI, Depends, HTTPException, Response
from authx import AuthX, AuthXConfig
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import os
from dotenv import load_dotenv

from database import engine, get_db
from models import User, Base
from schemas import UserCreate, UserLogin, UserDel

Base.metadata.create_all(bind=engine) #создание бд при запуске приложения(на случай если она будет отсутсвовать)
app = FastAPI()
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto') #схема хэша "bcrypt"
load_dotenv() #загружаем переменные из файла .env

# -------config-------
config = AuthXConfig()
config.JWT_SECRET_KEY = (
    os.getenv('JWT_SECRET_KEY') #получаем секретный ключ из окружения
)
config.JWT_ACCESS_COOKIE_NAME = (
    os.getenv('JWT_ACCESS_COOKIE_NAME')
)
config.JWT_TOKEN_LOCATION = ["cookies"]

security = AuthX(config=config)
config = AuthXConfig()
config.JWT_SECRET_KEY = 'jwt_sk' #ключ проверки токена (создавать в .env пространстве)
config.JWT_ACCESS_COOKIE_NAME = 'access_token'
config.JWT_TOKEN_LOCATION = ['cookies'] #расположение токена (куки/заголовки)

security = AuthX(config=config)

# -------commands-------
@app.post('/register')
def register(user_data: UserCreate, db: Session = Depends(get_db)): #создает параметр user_data который сотрудничает с UserCreate и вызывает БД
    existing_user = (
        db.query(User).filter(User.username == user_data.username).first() #ищет пользователя с таким же юзернеймом 
    )
    if existing_user:
        raise HTTPException(status_code=400, detail='Username already registered') #при нахождении такого выдает ошибку что чел зареган

    hashed_pw = pwd_context.hash(user_data.password) #название переменной хэширования пароля

    new_user = User(username = user_data.username, hashed_pw = hashed_pw) #добавляет юзера в БД
    db.add(new_user) #ставит в очередь добавления
    db.commit() #сохраняет БД
    db.refresh(new_user) #обновляет БД

    return {'message': 'user registered!'}



@app.delete('/delete-user')
def delete_user(user_data: UserDel,current_user_id: str = Depends(
        security.access_token_required
    ),
    db: Session = Depends(get_db)):
    
    current_admin = (
        db.query(User).filter(User.id == int(current_user_id)).first() #проверяем, является ли тот, кто отправляет запрос, администратором
    )
    if not current_admin or not current_admin.is_admin:
        raise HTTPException(
            status_code=403, detail="Not enough privileges (Admin only)"
        )
    
    user_to_delete = db.query(User).filter(User.id == user_data.id).first() #ищем пользователя, которого нужно удалить, по переданному ID
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found") #если пользователя с таким ID в базе нет — возвращаем 404 ошибку

    db.delete(user_to_delete)
    db.commit()  #подтверждаем изменения в базе

    return {"message": f"User with ID {user_data.id} has been deleted!"}



@app.post('/login')
def login(
    user_data: UserLogin, response: Response, db: Session = Depends(get_db) #создает параметр user_data который сотрудничает с UserLogin и вызывает БД
    ):
    user = db.query(User).filter(User.username == user_data.username).first() #ищет пользователя с таким же юзернеймом
    if not user or not pwd_context.verify(                                    #проверяет логин и пароль
        user_data.password, user.hashed_pw
    ):
        raise HTTPException(status_code=401, detail='Incorrect username or password')
    access_token = security.create_access_token(uid=str(user.id)) #создает токен с id пользователя
    response.set_cookie(key=config.JWT_ACCESS_COOKIE_NAME, value=access_token) #добавляет токен в куки браузера

    return {'access_token': access_token, 'message': 'Logged in successfully!'}



@app.get('/auth')
def auth(user_id=Depends(security.access_token_required)): #проверяет токен из куков на подлинность, при ошибке не выполняет код ниже
    return {
        'message': 'You are logined!',
        'user_id_from_db_token': user_id
    }
