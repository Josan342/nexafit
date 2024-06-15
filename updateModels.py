from pydantic import BaseModel
from typing import Optional

class DietaUpdate(BaseModel):
    id_dieta: int
    nombre_dieta: str
    descripcion: Optional[str] = None
    calorias_objetivo: Optional[int] = 0
    proteinas_gramos: Optional[float] = 0
    carbohidratos_gramos: Optional[float] = 0
    grasas_gramos: Optional[float] = 0


class RutinaEjercicioUpdate(BaseModel):
    id_rutina: int
    id_ejercicio: int
    repeticiones: Optional[int]
    series: Optional[int]
    duracion_min: Optional[int]