from datetime import datetime
from decimal import Decimal
from pydantic import BaseModel
from typing import Optional

class AlimentoRead(BaseModel):
    nombre: str
    calorias: Optional[int]
    proteinas: Optional[float]
    carbohidratos: Optional[float]
    grasas: Optional[float]
    
    class Config:
        from_attributes = True

class AlimentoInfo(BaseModel):
    nombre: str
    cantidad: Decimal
    calorias: Decimal
    proteinas: Decimal
    carbohidratos: Decimal
    grasas: Decimal
    class Config:
        from_attributes = True


class EjercicioInfo(BaseModel):
    id_ejercicio:int
    nombre_ejercicio: str
    descripcion: Optional[str]
    grupo_muscular: str
    repeticiones: Optional[int]
    series: Optional[int]
    duracion_min: Optional[int]

class ProgresoEjercicioRead(BaseModel):
    id_progreso_ejercicio: int
    id_ejercicio: int
    fecha: datetime
    repeticiones: int
    peso_levantado: Optional[float] = None
    numero_series: int

    class Config:
        orm_mode = True

class ProgresoEjercicioCreate(BaseModel):
    id_progreso: int
    id_usuario: int
    id_ejercicio: int
    fecha: datetime
    repeticiones: int
    peso_levantado: Optional[Decimal]
    numero_series: int

class UsuarioRead(BaseModel):
    nombre: str
    correo_electronico: str
    nick_name:str

    class Config:
        from_attributes = True

class ProgresoRead(BaseModel):
    id_progreso: int
    fecha: datetime
    peso: Optional[float]
    porcentaje_grasa: Optional[float]
    observaciones: Optional[str]
    
    class Config:
        orm_mode = True
