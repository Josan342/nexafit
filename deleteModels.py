
from pydantic import BaseModel


class DietaAlimentoDelete(BaseModel):
    id_dieta: int
    id_alimento: int