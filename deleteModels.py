
from pydantic import BaseModel


class DietaAlimentoDelete(BaseModel):
    id_dieta: int
    id_alimento: int

class RutinaEjercicioDelete(BaseModel):
    id_rutina: int
    id_ejercicio: int