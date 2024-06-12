from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from enum import Enum

class GrupoMuscularEnum(str, Enum):
    pecho = 'pecho'
    espalda = 'espalda'
    piernas = 'piernas'
    brazos = 'brazos'
    hombros = 'hombros'
    abdomen = 'abdomen'

class CategoriaNombreEnum(str, Enum):
    peso_libre = 'peso libre'
    máquina = 'máquina'
    poleas = 'poleas'
    calistenia = 'calistenia'

class AlimentoBase(BaseModel):
    nombre: str
    calorias: Optional[int]
    proteinas: Optional[float]
    carbohidratos: Optional[float]
    grasas: Optional[float]

class CategoriaBase(BaseModel):
    nombre_categoria: CategoriaNombreEnum

class DietaBase(BaseModel):
    id_usuario: int
    nombre_dieta: str
    descripcion: Optional[str]
    calorias_objetivo: Optional[int]
    proteinas_gramos: Optional[float]
    carbohidratos_gramos: Optional[float]
    grasas_gramos: Optional[float]

class DietaAlimentoBase(BaseModel):
    id_dieta: int
    id_alimento: int
    cantidad: float
    unidad_medida: str

class EjercicioBase(BaseModel):
    nombre_ejercicio: str
    descripcion: Optional[str]
    grupo_muscular: GrupoMuscularEnum

class ProgresoBase(BaseModel):
    id_usuario: int
    fecha: datetime
    peso: Optional[float]
    porcentaje_grasa: Optional[float]
    observaciones: Optional[str]

class ProgresoEjercicioBase(BaseModel):
    id_progreso: int
    id_usuario: int
    id_ejercicio: int
    fecha: datetime
    repeticiones: int
    peso_levantado: float

class RutinaBase(BaseModel):
    id_usuario: int
    nombre_rutina: str
    descripcion: Optional[str]
    fecha_creacion: datetime

class RutinaEjercicioBase(BaseModel):
    id_rutina: int
    id_ejercicio: int
    repeticiones: Optional[int]
    series: Optional[int]
    duracion_min: Optional[int]

class UsuarioBase(BaseModel):
    nombre: str
    correo_electronico: str
    contrasena_hash: str

class JWTBase(BaseModel):
    type_token: str
    token:str

class Login(BaseModel):
    username: str
    contrasena: str