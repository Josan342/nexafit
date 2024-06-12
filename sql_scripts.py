import models
from sql_connection import SessionLocal, engine
from sqlalchemy.orm import Session
from sqlalchemy import desc
import re

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
