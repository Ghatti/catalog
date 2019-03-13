import os
import sys
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context

Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))


class User(Base):

    __tablename__ = "user"

    id = Column(Integer, primary_key = True)
    name = Column(String(250), nullable = False)
    email = Column(String(250), nullable = False, index = True)
    picture = Column(String(250))
    google_id = Column(String(250), unique = True)
    password_hash = Column(String(64))
    admin = Column(Boolean, default = False)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration = 600):
        s = Serializer(secret_key, expires_in = expiration)
        return s.dumps({"id": self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)

        try: 
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user_id = data["id"]
        return user_id

class Category(Base):
    __tablename__ = "category"

    id = Column(Integer, primary_key = True)
    name = Column(String(250), nullable = False, unique = True)

    @property
    def serialize(self):
        return {
            "name": self.name,
            "id": self.id
        }

class Item(Base):
    __tablename__ = "item"

    id = Column(Integer, primary_key = True)
    name = Column(String(250), nullable = False, unique = True)
    description = Column(String(250), nullable = False)
    category_id = Column(Integer, ForeignKey("category.id"))
    category = relationship(Category)
    creation_date = Column(DateTime, nullable = False)
    last_edited = Column(DateTime, nullable = False)
    user_id = Column(Integer, ForeignKey("user.id"))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            "name": self.name,
            "description": self.description,
            "id": self.id,
            "category_id": self.category_id,
            "creation_date": self.creation_date,
            "last_edited": self.last_edited
        }




engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)