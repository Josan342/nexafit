from datetime import datetime
from decimal import Decimal
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional
class UsuarioCreate(BaseModel):
    nombre: str 
    apellido1:str
    apellido2:str
    correo_electronico: str
    contrasena: str 
    nick_name:str
    descripcion: Optional[str] = None
    social_media: Optional[str] = None

class DiasSemanaEnum(str, Enum):
    lunes = "lunes"
    martes = "martes"
    mircoles = "mircoles"
    jueves = "jueves"
    viernes = "viernes"
    sbado = "sbado"
    domingo = "domingo"

class RutinaCreate(BaseModel):
    nombre_rutina: str
    descripcion: Optional[str]
    dias_semana: Optional[DiasSemanaEnum]

class DietaCreate(BaseModel):
    nombre_dieta: str
    descripcion: Optional[str]
    calorias_objetivo: Optional[int]= 0
    proteinas_gramos: Optional[Decimal]= 0
    carbohidratos_gramos: Optional[Decimal]= 0
    grasas_gramos: Optional[Decimal]= 0


class DietaAlimentoCreate(BaseModel):
    id_dieta: int
    id_alimento: int
    cantidad: Decimal

class ProgresoEjercicioCreate(BaseModel):
    id_ejercicio: int
    fecha: datetime
    repeticiones: int
    peso_levantado: Optional[Decimal]
    numero_series: int

class RutinaEjercicioCreate(BaseModel):
    id_rutina: int
    id_ejercicio: int
    repeticiones: Optional[int] = None
    series: Optional[int] = None
    duracion_min: Optional[int] = None
    
class ProgresoCreate(BaseModel):
    fecha: datetime
    peso: Optional[float]
    porcentaje_grasa: Optional[float]
    observaciones: Optional[str]


class DietaIdRequest(BaseModel):
    id_dieta: int

class RutinaIdRequest(BaseModel):
    id_rutina: int

class EjercicioIdRequest(BaseModel):
    id_ejercicio: int

class ProgresoIdRequest(BaseModel):
    id_progreso: int
