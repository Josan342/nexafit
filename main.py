from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError,jwt
from createModels import DietaAlimentoCreate, DietaCreate, DietaIdRequest, EjercicioIdRequest, ProgresoCreate, ProgresoEjercicioCreate, RutinaCreate, RutinaEjercicioCreate, RutinaIdRequest, UsuarioCreate
import crud
from database import get_db
from deleteModels import DietaAlimentoDelete, RutinaEjercicioDelete
from models import *
from readModels import AlimentoInfo, AlimentoRead, EjercicioInfo, ProgresoEjercicioRead, ProgresoRead,UsuarioRead
from schemas import *
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import Alimento,Usuario
import createModels
import bcrypt
import baseModels
from updateModels import DietaUpdate, RutinaEjercicioUpdate

app = FastAPI()
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"], 
)

SECRET_KEY = "posYoQueSeMiLoco"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 300

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def getUserID(request: Request, db:Session=Depends(get_db)):
    if hasattr(request.state, 'user'):
        user = crud.get_user_by_username(db,request.state.user)
        print("$$$$$$$$$$$$$$$$$$$$$$$$$$$")
        print(user.id_usuario)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        request.state.userID = user.id_usuario
        return request.state
    else:
        return request.state

def hash_password(usuario: UsuarioCreate) -> UsuarioCreate:
    hashed_password = bcrypt.hashpw(usuario.contrasena.encode('utf-8'), bcrypt.gensalt())
    usuario.contrasena = hashed_password.decode('utf-8')  
    return usuario

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Obtener todos los alimentos
@app.get("/alimentos/")
def get_alimentos( db: Session = Depends(get_db)):
    alimentos = db.query(Alimento).all()
    return alimentos

@app.get("/ejercicios/")
def get_ejercicios( db: Session = Depends(get_db)):
    ejercicios = db.query(Ejercicio).all()
    return ejercicios

@app.get("/alimentos/{nombre_alimento}", response_model=AlimentoRead)
def read_alimento(nombre_alimento: str, db: Session = Depends(get_db)):
    db_alimento = crud.get_alimento_by_nombre(db, nombre=nombre_alimento)
    if db_alimento is None:
        raise HTTPException(status_code=404, detail="Alimento no encontrado")
    return db_alimento

@app.get("/ejercicios/{nombre_ejercicio}")
def read_alimento(nombre_ejercicio: str, db: Session = Depends(get_db)):
    db_alimento = crud.get_ejercicio_by_name(db, nombre=nombre_ejercicio)
    if db_alimento is None:
        raise HTTPException(status_code=404, detail="Ejercicio no encontrado")
    return db_alimento

@app.post("/register", response_model=UsuarioRead)
def crear_usuario(usuario: createModels.UsuarioCreate = Depends(hash_password), db: Session = Depends(get_db)):
    try:
        print("Inicio del registro de usuario")
        db_user = crud.get_usuario_by_email(db, email=usuario.correo_electronico)
        if db_user:
            print("Correo electrónico ya está en uso")
            raise HTTPException(status_code=400, detail="El correo ya está registrado")

        print("Creando usuario")
        db_user = Usuario(
            nombre=usuario.nombre,
            correo_electronico=usuario.correo_electronico,
            contrasena_hash=usuario.contrasena,
            apellido1=usuario.apellido1,
            apellido2=usuario.apellido2
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        print("Usuario creado con éxito")

        print("Creando detalles del perfil")
        detalle_perfil = DetallePerfil(
            id_usuario=db_user.id_usuario,
            nick_name=usuario.nick_name,
        )
        if usuario.descripcion:
            detalle_perfil.descripcion = usuario.descripcion
        if usuario.social_media:
            detalle_perfil.social_media = usuario.social_media

        db.add(detalle_perfil)
        db.commit()
        db.refresh(detalle_perfil)
        print("Detalles del perfil creados con éxito")

        usuario_read = UsuarioRead(
            nombre=db_user.nombre,
            correo_electronico=db_user.correo_electronico,
            nick_name=detalle_perfil.nick_name
        )
        print("Registro de usuario completado con éxito")
        return usuario_read

    except HTTPException as http_exc:
        print(f"HTTPException: {http_exc.detail}")
        raise http_exc
    except Exception as e:
        print(f"Error inesperado: {str(e)}")
        raise HTTPException(status_code=500, detail="Error en el registro del usuario")


@app.post("/login",response_model=baseModels.JWTBase)
async def login_for_access_token(login:baseModels.Login, db: Session = Depends(get_db)):

    if crud.verify_user(db,login):
        print("entra")
        user_dict = {"username": login.username, "password": login.contrasena}
        access_token = create_access_token(data=user_dict)
        return {"type_token": "Bearer","token":access_token}
    else:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
@app.middleware("http")
async def verify_jwt(request: Request, call_next):

    bypass_routes = ["/docs", "/openapi.json", "/redoc","/login","/register","/"]

    if request.url.path not in bypass_routes:
        token = request.headers.get("Authorization", "").split(" ")[-1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            request.state.user = payload.get("username")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    response = await call_next(request)
    return response

@app.get("/get-rutinas")
def get_rutinas(db: Session = Depends(get_db), state = Depends(getUserID)):
    rutinas = db.query(Rutina).filter(Rutina.id_usuario == state.userID).all()
    if not rutinas:
        raise HTTPException(status_code=404, detail="No se encontraron rutinas para este usuario")
    
    return [
        {
            "id_rutina": rutina.id_rutina,
            "nombre_rutina": rutina.nombre_rutina,
            "descripcion": rutina.descripcion,
            "dias_semana": rutina.dias_semana,
            "fecha_creacion": rutina.fecha_creacion
        }
        for rutina in rutinas
    ]

from datetime import datetime

@app.get("/get-rutinas-dia")
def get_rutinas_dia(db: Session = Depends(get_db), state = Depends(getUserID)):
    dia_actual = datetime.now().strftime('%A').lower()
    dias_semana_map = {
        'monday': 'lunes',
        'tuesday': 'martes',
        'wednesday': 'mircoles',
        'thursday': 'jueves',
        'friday': 'viernes',
        'saturday': 'sbado',
        'sunday': 'domingo'
    }
    dia_actual_spanish = dias_semana_map[dia_actual]
    
    rutinas = db.query(Rutina).filter(Rutina.id_usuario == state.userID, Rutina.dias_semana == dia_actual_spanish).all()
    if not rutinas:
        raise HTTPException(status_code=404, detail="No se encontraron rutinas para este día")
    
    return [
        {
            "id_rutina": rutina.id_rutina,
            "nombre_rutina": rutina.nombre_rutina,
            "descripcion": rutina.descripcion,
            "dias_semana": rutina.dias_semana,
            "fecha_creacion": rutina.fecha_creacion
        }
        for rutina in rutinas
    ]


@app.get("/get-dietas")
def get_dietas(db: Session = Depends(get_db), state = Depends(getUserID)):
    dietas = db.query(Dieta).filter(Dieta.id_usuario == state.userID).all()
    if not dietas:
        raise HTTPException(status_code=404, detail="No se encontraron dietas para este usuario")
    
    return [
        {
            "id_dieta": dieta.id_dieta,
            "nombre_dieta": dieta.nombre_dieta,
            "descripcion": dieta.descripcion,
            "calorias_objetivo": dieta.calorias_objetivo,
            "calorias_totales": dieta.calorias_totales,
            "proteinas_gramos": dieta.proteinas_gramos,
            "carbohidratos_gramos": dieta.carbohidratos_gramos,
            "grasas_gramos": dieta.grasas_gramos,
            "proteinas_totales": dieta.proteinas_totales,
            "carbohidratos_totales": dieta.carbohidratos_totales,
            "grasas_totales": dieta.grasas_totales
        }
        for dieta in dietas
    ]

@app.post("/create-dieta")
def create_dieta(dieta: DietaCreate, db: Session = Depends(get_db), state = Depends(getUserID)):
    db_dieta = Dieta(
        id_usuario=state.userID,
        nombre_dieta=dieta.nombre_dieta,
        descripcion=dieta.descripcion,
        calorias_objetivo=dieta.calorias_objetivo,
        proteinas_gramos=dieta.proteinas_gramos,
        carbohidratos_gramos=dieta.carbohidratos_gramos,
        grasas_gramos=dieta.grasas_gramos
    )
    db.add(db_dieta)
    db.commit()
    db.refresh(db_dieta)
    return db_dieta

@app.post("/create-rutina")
def create_rutina(rutina: RutinaCreate, db: Session = Depends(get_db), state = Depends(getUserID)):
    print(rutina.dias_semana.name)
    print(rutina.dias_semana.value)
    db_rutina = Rutina(
        id_usuario=state.userID,
        nombre_rutina=rutina.nombre_rutina,
        descripcion=rutina.descripcion,
        dias_semana=rutina.dias_semana
    )
    db.add(db_rutina)
    db.commit()
    db.refresh(db_rutina)
    return db_rutina


@app.post("/update-ejercicio-rutina")
def update_ejercicio_rutina(rutina_ejercicio: RutinaEjercicioUpdate, db: Session = Depends(get_db)):
    db_rutina_ejercicio = db.query(RutinaEjercicio).filter(
        RutinaEjercicio.id_rutina == rutina_ejercicio.id_rutina,
        RutinaEjercicio.id_ejercicio == rutina_ejercicio.id_ejercicio
    ).first()

    if not db_rutina_ejercicio:
        raise HTTPException(status_code=404, detail="Ejercicio en la rutina no encontrado")

    if rutina_ejercicio.repeticiones is not None:
        db_rutina_ejercicio.repeticiones = rutina_ejercicio.repeticiones
    if rutina_ejercicio.series is not None:
        db_rutina_ejercicio.series = rutina_ejercicio.series
    if rutina_ejercicio.duracion_min is not None:
        db_rutina_ejercicio.duracion_min = rutina_ejercicio.duracion_min

    db.commit()
    db.refresh(db_rutina_ejercicio)
    return {"message": "Ejercicio actualizado en la rutina"}

@app.post("/delete-ejercicio-rutina")
def delete_ejercicio_rutina(rutina_ejercicio: RutinaEjercicioDelete, db: Session = Depends(get_db)):
    db_rutina_ejercicio = db.query(RutinaEjercicio).filter(
        RutinaEjercicio.id_rutina == rutina_ejercicio.id_rutina,
        RutinaEjercicio.id_ejercicio == rutina_ejercicio.id_ejercicio
    ).first()

    if not db_rutina_ejercicio:
        raise HTTPException(status_code=404, detail="Ejercicio en la rutina no encontrado")

    db.delete(db_rutina_ejercicio)
    db.commit()
    return {"message": "Ejercicio eliminado de la rutina"}


@app.post("/delete-alimento-dieta")
def delete_alimento_dieta(dieta_alimento: DietaAlimentoDelete, db: Session = Depends(get_db)):
    db_dieta = db.query(Dieta).filter(Dieta.id_dieta == dieta_alimento.id_dieta).first()
    if not db_dieta:
        raise HTTPException(status_code=404, detail="Dieta no encontrada")

    db_alimento = db.query(DietaAlimento).filter(
        DietaAlimento.id_dieta == dieta_alimento.id_dieta,
        DietaAlimento.id_alimento == dieta_alimento.id_alimento
    ).first()
    if not db_alimento:
        raise HTTPException(status_code=404, detail="Alimento no encontrado en la dieta")

    cantidad_factor = db_alimento.cantidad / 100

    db_dieta.calorias_totales -= db_alimento.alimento.calorias * cantidad_factor
    db_dieta.proteinas_totales -= db_alimento.alimento.proteinas * cantidad_factor
    db_dieta.carbohidratos_totales -= db_alimento.alimento.carbohidratos * cantidad_factor
    db_dieta.grasas_totales -= db_alimento.alimento.grasas * cantidad_factor

    db.delete(db_alimento)
    db.commit()
    db.refresh(db_dieta)

    return {"message": "Alimento eliminado de la dieta y valores actualizados"}



@app.post("/update-alimento-dieta")
def update_alimento_dieta(dieta_alimento: DietaAlimentoCreate, db: Session = Depends(get_db)):
    db_dieta = db.query(Dieta).filter(Dieta.id_dieta == dieta_alimento.id_dieta).first()
    if not db_dieta:
        raise HTTPException(status_code=404, detail="Dieta no encontrada")

    db_alimento = db.query(DietaAlimento).filter(
        DietaAlimento.id_dieta == dieta_alimento.id_dieta,
        DietaAlimento.id_alimento == dieta_alimento.id_alimento
    ).first()
    if not db_alimento:
        raise HTTPException(status_code=404, detail="Alimento no encontrado en la dieta")

    # Revertir los valores antiguos
    cantidad_factor_old = db_alimento.cantidad / 100
    db_dieta.calorias_totales -= db_alimento.alimento.calorias * cantidad_factor_old
    db_dieta.proteinas_totales -= db_alimento.alimento.proteinas * cantidad_factor_old
    db_dieta.carbohidratos_totales -= db_alimento.alimento.carbohidratos * cantidad_factor_old
    db_dieta.grasas_totales -= db_alimento.alimento.grasas * cantidad_factor_old

    # Actualizar los valores
    db_alimento.cantidad = dieta_alimento.cantidad

    cantidad_factor_new = dieta_alimento.cantidad / 100
    db_dieta.calorias_totales += db_alimento.alimento.calorias * cantidad_factor_new
    db_dieta.proteinas_totales += db_alimento.alimento.proteinas * cantidad_factor_new
    db_dieta.carbohidratos_totales += db_alimento.alimento.carbohidratos * cantidad_factor_new
    db_dieta.grasas_totales += db_alimento.alimento.grasas * cantidad_factor_new

    db.commit()
    db.refresh(db_dieta)
    db.refresh(db_alimento)

    return {"message": "Alimento actualizado en la dieta y valores actualizados"}


@app.post("/add-alimento-dieta")
def add_alimento_dieta(dieta_alimento: DietaAlimentoCreate, db: Session = Depends(get_db)):
    db_dieta = db.query(Dieta).filter(Dieta.id_dieta == dieta_alimento.id_dieta).first()
    if not db_dieta:
        raise HTTPException(status_code=404, detail="Dieta no encontrada")

    db_alimento = db.query(Alimento).filter(Alimento.id_alimento == dieta_alimento.id_alimento).first()
    if not db_alimento:
        raise HTTPException(status_code=404, detail="Alimento no encontrado")

    # Verificar si el alimento ya está en la dieta
    existe_dieta_alimento = db.query(DietaAlimento).filter(
        DietaAlimento.id_dieta == dieta_alimento.id_dieta,
        DietaAlimento.id_alimento == dieta_alimento.id_alimento
    ).first()

    if existe_dieta_alimento:
        raise HTTPException(status_code=400, detail="El alimento ya está añadido a la dieta")

    nuevo_dieta_alimento = DietaAlimento(
        id_dieta=dieta_alimento.id_dieta,
        id_alimento=dieta_alimento.id_alimento,
        cantidad=dieta_alimento.cantidad,
        unidad_medida="gramos"
    )
    db.add(nuevo_dieta_alimento)

    cantidad_factor = dieta_alimento.cantidad / 100

    db_dieta.calorias_totales += db_alimento.calorias * cantidad_factor
    db_dieta.proteinas_totales += db_alimento.proteinas * cantidad_factor
    db_dieta.carbohidratos_totales += db_alimento.carbohidratos * cantidad_factor
    db_dieta.grasas_totales += db_alimento.grasas * cantidad_factor

    db.commit()
    db.refresh(db_dieta)
    db.refresh(nuevo_dieta_alimento)

    return {"message": "Alimento añadido a la dieta y valores actualizados"}

@app.post("/add-ejercicio-rutina")
def add_ejercicio_rutina(rutina_ejercicio: RutinaEjercicioCreate, db: Session = Depends(get_db)):
    db_rutina = db.query(Rutina).filter(Rutina.id_rutina == rutina_ejercicio.id_rutina).first()
    if not db_rutina:
        raise HTTPException(status_code=404, detail="Rutina no encontrada")

    db_ejercicio = db.query(Ejercicio).filter(Ejercicio.id_ejercicio == rutina_ejercicio.id_ejercicio).first()
    if not db_ejercicio:
        raise HTTPException(status_code=404, detail="Ejercicio no encontrado")

    nuevo_rutina_ejercicio = RutinaEjercicio(
        id_rutina=rutina_ejercicio.id_rutina,
        id_ejercicio=rutina_ejercicio.id_ejercicio,
        repeticiones=rutina_ejercicio.repeticiones,
        series=rutina_ejercicio.series,
        duracion_min=rutina_ejercicio.duracion_min
    )
    db.add(nuevo_rutina_ejercicio)
    db.commit()
    db.refresh(nuevo_rutina_ejercicio)
    return nuevo_rutina_ejercicio



@app.post("/dieta/alimentos")
def get_dieta_alimentos(dieta_id_request: DietaIdRequest, db: Session = Depends(get_db)):
    id_dieta = dieta_id_request.id_dieta

    db_dieta = db.query(Dieta).filter(Dieta.id_dieta == id_dieta).first()
    if not db_dieta:
        raise HTTPException(status_code=404, detail="Dieta no encontrada")

    alimentos = (
        db.query(DietaAlimento, Alimento)
        .join(Alimento, DietaAlimento.id_alimento == Alimento.id_alimento)
        .filter(DietaAlimento.id_dieta == id_dieta)
        .all()
    )

    alimentos_info = []
    for dieta_alimento, alimento in alimentos:
        cantidad_factor = dieta_alimento.cantidad / 100
        alimentos_info.append(
            AlimentoInfo(
                id_alimento=alimento.id_alimento,
                nombre=alimento.nombre,
                cantidad=dieta_alimento.cantidad,
                calorias=alimento.calorias * cantidad_factor,
                proteinas=alimento.proteinas * cantidad_factor,
                carbohidratos=alimento.carbohidratos * cantidad_factor,
                grasas=alimento.grasas * cantidad_factor,
            )
        )

    for alimento in alimentos_info:
        print
    return alimentos_info


@app.post("/update-dieta")
def update_dieta(dieta_update: DietaUpdate, db: Session = Depends(get_db), state = Depends(getUserID)):
    db_dieta = db.query(Dieta).filter(Dieta.id_dieta == dieta_update.id_dieta, Dieta.id_usuario == state.userID).first()
    if not db_dieta:
        raise HTTPException(status_code=404, detail="Dieta no encontrada")
    
    db_dieta.nombre_dieta = dieta_update.nombre_dieta
    db_dieta.descripcion = dieta_update.descripcion
    db_dieta.calorias_objetivo = dieta_update.calorias_objetivo
    db_dieta.proteinas_gramos = dieta_update.proteinas_gramos
    db_dieta.carbohidratos_gramos = dieta_update.carbohidratos_gramos
    db_dieta.grasas_gramos = dieta_update.grasas_gramos

    db.commit()
    db.refresh(db_dieta)

    return {"message": "Dieta actualizada con éxito", "dieta": db_dieta}

@app.post("/delete-dieta")
def delete_dieta(dieta_id_request: DietaIdRequest, db: Session = Depends(get_db), state = Depends(getUserID)):
    id_dieta = dieta_id_request.id_dieta
    
    # Verificar si la dieta existe
    db_dieta = db.query(Dieta).filter(Dieta.id_dieta == id_dieta).first()
    if not db_dieta:
        raise HTTPException(status_code=404, detail="Dieta no encontrada")
    
    # Verificar que la dieta pertenece al usuario que hace la solicitud
    if db_dieta.id_usuario != state.userID:
        raise HTTPException(status_code=403, detail="No tiene permiso para eliminar esta dieta")
    
    # Eliminar todas las relaciones en la tabla dieta_alimento
    db.query(DietaAlimento).filter(DietaAlimento.id_dieta == id_dieta).delete()
    
    # Eliminar la dieta
    db.delete(db_dieta)
    db.commit()
    
    return {"message": "Dieta eliminada con éxito"}


@app.post("/rutina/ejercicios")
def get_rutina_ejercicios(rutina_id_request: RutinaIdRequest, db: Session = Depends(get_db)):
    id_rutina = rutina_id_request.id_rutina
    print(id_rutina)

    db_rutina = db.query(Rutina).filter(Rutina.id_rutina == id_rutina).first()
    if not db_rutina:
        raise HTTPException(status_code=404, detail="Rutina no encontrada")

    ejercicios = (
        db.query(RutinaEjercicio, Ejercicio)
        .join(Ejercicio, RutinaEjercicio.id_ejercicio == Ejercicio.id_ejercicio)
        .filter(RutinaEjercicio.id_rutina == id_rutina)
        .all()
    )

    # Crear la lista de información de ejercicios
    ejercicios_info = []
    for rutina_ejercicio, ejercicio in ejercicios:
        ejercicios_info.append(
            EjercicioInfo(
                id_ejercicio=ejercicio.id_ejercicio,
                nombre_ejercicio=ejercicio.nombre_ejercicio,
                descripcion=ejercicio.descripcion,
                grupo_muscular=ejercicio.grupo_muscular,
                repeticiones=rutina_ejercicio.repeticiones,
                series=rutina_ejercicio.series,
                duracion_min=rutina_ejercicio.duracion_min
            )
        )

    return ejercicios_info

@app.post("/create-progreso-ejercicio")
def create_progreso_ejercicio(progreso_ejercicio: ProgresoEjercicioCreate, db: Session = Depends(get_db),state = Depends(getUserID)):

    db_usuario = db.query(Usuario).filter(Usuario.id_usuario == state.userID).first()
    if not db_usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db_ejercicio = db.query(Ejercicio).filter(Ejercicio.id_ejercicio == progreso_ejercicio.id_ejercicio).first()
    if not db_ejercicio:
        raise HTTPException(status_code=404, detail="Ejercicio no encontrado")

    nuevo_progreso_ejercicio = ProgresoEjercicio(
        id_usuario=state.userID,
        id_ejercicio=progreso_ejercicio.id_ejercicio,
        fecha=progreso_ejercicio.fecha,
        repeticiones=progreso_ejercicio.repeticiones,
        peso_levantado=progreso_ejercicio.peso_levantado,
        numero_series=progreso_ejercicio.numero_series
    )
    db.add(nuevo_progreso_ejercicio)
    db.commit()
    db.refresh(nuevo_progreso_ejercicio)
    return nuevo_progreso_ejercicio

@app.post("/progreso/ejercicio", response_model=List[ProgresoEjercicioRead])
def get_progreso_ejercicio(ejercicio_id_request: EjercicioIdRequest, db: Session = Depends(get_db), state = Depends(getUserID)):
    id_ejercicio = ejercicio_id_request.id_ejercicio

    # Verificar si el ejercicio existe
    db_ejercicio = db.query(Ejercicio).filter(Ejercicio.id_ejercicio == id_ejercicio).first()
    if not db_ejercicio:
        raise HTTPException(status_code=404, detail="Ejercicio no encontrado")

    # Obtener el progreso del ejercicio para el usuario actual
    progreso = db.query(ProgresoEjercicio).filter(
        ProgresoEjercicio.id_usuario == state.userID,
        ProgresoEjercicio.id_ejercicio == id_ejercicio
    ).all()

    return progreso


@app.get("/progresos", response_model=List[ProgresoRead])
def get_progresos(db: Session = Depends(get_db),state = Depends(getUserID)):
    progresos = db.query(Progreso).filter(Progreso.id_usuario == state.userID).all()
    return progresos

@app.post("/progresos", response_model=ProgresoRead)
def create_progreso(progreso: ProgresoCreate, db: Session = Depends(get_db),state = Depends(getUserID)):
    db_progreso = Progreso(
        id_usuario=state.userID,
        fecha=progreso.fecha,
        peso=progreso.peso,
        porcentaje_grasa=progreso.porcentaje_grasa,
        observaciones=progreso.observaciones
    )
    db.add(db_progreso)
    db.commit()
    db.refresh(db_progreso)
    return db_progreso