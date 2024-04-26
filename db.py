from flask_pymongo import PyMongo
from flask import current_app, g
from config import Config

def get_db():
    if 'db' not in g:
        try:
            current_app.config.from_object(Config)
            g.db = PyMongo(current_app).db
            current_app.logger.info("Database connection successfully established.")
        except Exception as e:
            current_app.logger.error(f"Failed to connect to the database: {e}")
            current_app.logger.error(e, exc_info=True)
    return g.db