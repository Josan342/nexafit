from sqlalchemy.orm import Session
from baseModels import Login
from models import Alimento, DetallePerfil, Ejercicio,Usuario
import bcrypt
def get_alimento_by_nombre(db: Session, nombre: str):
    return db.query(Alimento).filter(Alimento.nombre == nombre).first()

def get_ejercicio_by_name(db: Session, nombre: str):
    return db.query(Ejercicio).filter(Ejercicio.nombre_ejercicio == nombre).first()

def get_usuario_by_email(db: Session, email: str):
    return db.query(Usuario).filter(Usuario.correo_electronico == email).first()

def verify_user(db: Session, login: Login):
    userProfile = db.query(DetallePerfil).filter(DetallePerfil.nick_name == login.username).first()
    if userProfile is None:
        return False
    user=db.query(Usuario).filter(Usuario.id_usuario==userProfile.id_usuario).first()
    password_provided_bytes = login.contrasena.encode('utf-8')
    password_hashed_bytes = user.contrasena_hash.encode('utf-8')

    
    return bcrypt.checkpw(password_provided_bytes, password_hashed_bytes)

def get_user_by_username(db:Session,username:str):
    userProfile = db.query(DetallePerfil).filter(DetallePerfil.nick_name == username).first()
    return db.query(Usuario).filter(userProfile.id_usuario==Usuario.id_usuario).first()