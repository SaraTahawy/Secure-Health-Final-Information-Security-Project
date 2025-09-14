# secure_health_app/database.py
from flask_sqlalchemy import SQLAlchemy
import bcrypt

# Initialize SQLAlchemy for database interactions
db = SQLAlchemy()
# Initialize bcrypt for password hashing
bcrypt = bcrypt