from sqlalchemy import Column, String, Integer, Float, ForeignKey
from sqlalchemy.orm import relationship

from project.setup.db import models


class Genre(models.Base):
    __tablename__ = 'genres'

    name = Column(String(100), unique=True, nullable=False)


class Director(models.Base):
    __tablename__ = 'directors'

    name = Column(String(100), unique=True, nullable=False)

class Movie(models.Base):
    __tablename__ = 'movies'

    title = Column(String(255), nullable=False)
    description = Column(String(255), nullable=False)
    trailer = Column(String(255), nullable=False)
    year = Column(Integer, nullable=False)
    rating = Column(Float, nullable=False)
    genre_id = Column(Integer, ForeignKey(f"{Genre.__tablename__}.id"), nullable=False)
    director_id = Column(Integer, ForeignKey(f"{Director.__tablename__}.id"), nullable=False)
    genre = relationship("Genre")
    director = relationship("Director")

class User(models.Base):
    __tablename__ = 'users'

    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(300), nullable=False)
    name = Column(String(30))
    surname = Column(String(30))
    favorite_genre = Column(Integer, ForeignKey(f"{Genre.__tablename__}.id"))







