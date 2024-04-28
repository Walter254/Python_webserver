from pymongo import MongoClient
from pymongo.server_api import ServerApi
from flask import current_app, g, has_app_context, abort, Flask
import os

class Config:
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://wagudewalter2:wwowA2016@cluster0.6ea9hhs.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')

def get_client():
    """Create and return a MongoDB client using the application's config."""
    return MongoClient(Config.MONGO_URI, server_api=ServerApi('1'))

def close_db(e=None):
    """Closes the database connection at the end of the request."""
    if 'db_client' in g:
        g.pop('db_client').close()

def get_db():
    """Gets a database connection from the global object, creating one if not already present."""
    if 'db_client' not in g:
        if not has_app_context():
            abort(500, description="No application context found.")
        try:
            g.db_client = get_client()
            g.db_client.admin.command('ping')
            current_app.logger.info("Database connection successfully established.")
        except Exception as e:
            current_app.logger.error(f"Failed to connect to the database: {e}")
            abort(500, description="Database connection failed.")
    return g.db_client['test']  # Directly return the 'test' database

def init_app(app):
    """Initializes application with necessary teardown handlers."""
    app.teardown_appcontext(close_db)

def create_app():
    """Application factory to create Flask app instances."""
    app = Flask(__name__)
    init_app(app)
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
