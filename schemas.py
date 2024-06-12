from pydantic import BaseModel
from typing import List, Optional

class AlimentoModel(BaseModel):
    id_alimento: int
    nombre: str
    calorias: Optional[int] = None
    proteinas: Optional[float] = None
    carbohidratos: Optional[float] = None
    grasas: Optional[float] = None

class CategoriaModel(BaseModel):
    id_categoria: int
    nombre_categoria: str

class DietaModel(BaseModel):
    id_dieta: int
    id_usuario: int
    nombre_dieta: str
    descripcion: Optional[str] = None
    calorias_objetivo: Optional[int] = None
    proteinas_gramos: Optional[float] = None
    carbohidratos_gramos: Optional[float] = None
    grasas_gramos: Optional[float] = None

class DietaAlimentoModel(BaseModel):
    id_dieta: int
    id_alimento: int
    cantidad: Optional[float] = None
    unidad_medida: Optional[str] = None

class EjercicioModel(BaseModel):
    id_ejercicio: int
    nombre_ejercicio: str
    descripcion: Optional[str] = None
    grupo_muscular: str

class EjercicioCategoriaModel(BaseModel):
    id_ejercicio: int
    id_categoria: int

class ProgresoModel(BaseModel):
    id_progreso: int
    id_usuario: int
    fecha: str
    peso: Optional[float] = None
    porcentaje_grasa: Optional[float] = None
    observaciones: Optional[str] = None

class ProgresoEjercicioModel(BaseModel):
    id_progreso: int
    id_usuario: int
    id_ejercicio: int
    fecha: str
    repeticiones: int
    peso_levantado: Optional[float] = None

class RutinaModelModel(BaseModel):
    id_rutina: int
    id_usuario: int
    nombre_rutina: str
    descripcion: Optional[str] = None
    fecha_creacion: str

class RutinaEjercicioModel(BaseModel):
    id_rutina: int
    id_ejercicio: int
    repeticiones: Optional[int] = None
    series: Optional[int] = None
    duracion_min: Optional[int] = None

class UsuarioModel(BaseModel):
    id_usuario: int
    nombre: str
    correo_electronico: str
    contrasena_hash: str
    fecha_registro: str
    ultimo_acceso: Optional[str] = None


