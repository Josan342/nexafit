from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, DECIMAL, ForeignKey,func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.mysql import ENUM
from sqlalchemy.orm import relationship

Base = declarative_base()

class Alimento(Base):
    __tablename__ = 'alimento'
    id_alimento = Column(Integer, primary_key=True)
    nombre = Column(String(255), nullable=False)
    calorias = Column(Integer)
    proteinas = Column(DECIMAL(5,2))
    carbohidratos = Column(DECIMAL(5,2))
    grasas = Column(DECIMAL(5,2))

class Categoria(Base):
    __tablename__ = 'categoria'
    id_categoria = Column(Integer, primary_key=True)
    nombre_categoria = Column(Enum('peso libre','mquina','poleas','calistenia'), nullable=False)

class Dieta(Base):
    __tablename__ = 'dieta'
    id_dieta = Column(Integer, primary_key=True)
    id_usuario = Column(Integer, ForeignKey('usuario.id_usuario'), nullable=False)
    nombre_dieta = Column(String(255), nullable=False)
    descripcion = Column(Text, nullable=True)
    calorias_objetivo = Column(DECIMAL(8,2), default=0)
    calorias_totales = Column(DECIMAL(8,2), default=0)
    proteinas_gramos = Column(DECIMAL(8,2), default=0)
    carbohidratos_gramos = Column(DECIMAL(8,2), default=0)
    grasas_gramos = Column(DECIMAL(8,2), default=0)
    proteinas_totales = Column(DECIMAL(8,2), default=0)
    carbohidratos_totales = Column(DECIMAL(8,2), default=0)
    grasas_totales = Column(DECIMAL(8,2), default=0)



class DietaAlimento(Base):
    __tablename__ = 'dieta_alimento'
    id_dieta = Column(Integer, ForeignKey('dieta.id_dieta'), primary_key=True)
    id_alimento = Column(Integer, ForeignKey('alimento.id_alimento'), primary_key=True)
    cantidad = Column(DECIMAL(10,2))
    unidad_medida = Column(String(50))

class Ejercicio(Base):
    __tablename__ = 'ejercicio'
    id_ejercicio = Column(Integer, primary_key=True)
    nombre_ejercicio = Column(String(255), nullable=False)
    descripcion = Column(Text)
    grupo_muscular = Column(Enum('pecho','espalda','piernas','brazos','hombros','abdomen'), nullable=False)

class EjercicioCategoria(Base):
    __tablename__ = 'ejercicio_categoria'
    id_ejercicio = Column(Integer, ForeignKey('ejercicio.id_ejercicio'), primary_key=True)
    id_categoria = Column(Integer, ForeignKey('categoria.id_categoria'), primary_key=True)

class Progreso(Base):
    __tablename__ = 'progreso'
    id_progreso = Column(Integer, primary_key=True)
    id_usuario = Column(Integer, ForeignKey('usuario.id_usuario'), nullable=False)
    fecha = Column(DateTime, nullable=False)
    peso = Column(DECIMAL(5,2))
    porcentaje_grasa = Column(DECIMAL(5,2), nullable=True)
    observaciones = Column(Text)

class ProgresoEjercicio(Base):
    __tablename__ = 'progreso_ejercicio'
    id_progreso_ejercicio = Column(Integer, primary_key=True)
    id_usuario = Column(Integer, ForeignKey('usuario.id_usuario'))
    id_ejercicio = Column(Integer, ForeignKey('ejercicio.id_ejercicio'))
    fecha = Column(DateTime, nullable=False)
    repeticiones = Column(Integer, nullable=False)
    peso_levantado = Column(DECIMAL(10,2))
    numero_series = Column(Integer, nullable=False)

class Rutina(Base):
    __tablename__ = 'rutina'
    id_rutina = Column(Integer, primary_key=True)
    id_usuario = Column(Integer, ForeignKey('usuario.id_usuario'), nullable=False)
    nombre_rutina = Column(String(255), nullable=False)
    descripcion = Column(Text)
    dias_semana = Column(Enum('lunes', 'martes', 'mircoles', 'jueves', 'viernes', 'sbado', 'domingo'))
    fecha_creacion = Column(DateTime, server_default=func.current_timestamp())
class RutinaEjercicio(Base):
    __tablename__ = 'rutina_ejercicio'
    id_rutina = Column(Integer, ForeignKey('rutina.id_rutina'), primary_key=True)
    id_ejercicio = Column(Integer, ForeignKey('ejercicio.id_ejercicio'), primary_key=True)
    repeticiones = Column(Integer)
    series = Column(Integer)
    duracion_min = Column(Integer)

class Usuario(Base):
    __tablename__ = 'usuario'
    id_usuario = Column(Integer, primary_key=True)
    nombre = Column(String(255), nullable=False)
    apellido1 = Column(String(255), nullable=False)
    apellido2 = Column(String(255), nullable=False)
    correo_electronico = Column(String(255), nullable=False, unique=True)
    contrasena_hash = Column(String(255), nullable=False)
    fecha_registro = Column(DateTime, server_default=func.current_timestamp())
    ultimo_acceso = Column(DateTime)

class DetallePerfil(Base):
    __tablename__ = 'detalle_perfil'
    id_usuario = Column(Integer, ForeignKey('usuario.id_usuario'), primary_key=True)
    nick_name = Column(String(255), unique=True)
    playlist = Column(String(255)) 
    social_media = Column(String(255)) 
    descripcion = Column(Text)


