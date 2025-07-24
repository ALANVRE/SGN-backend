from fastapi import FastAPI, Depends, HTTPException, Header
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Float
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import List, Optional
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import json

# Configuración DB
SQLALCHEMY_DATABASE_URL = "postgresql+psycopg2://postgres:12345@localhost:5432/unidad"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# Modelos
class Profesor(Base):
    __tablename__ = "profesores"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    hashed_password = Column(String)
    cursos = relationship("Curso", back_populates="profesor")

class Curso(Base):
    __tablename__ = "cursos"
    id = Column(Integer, primary_key=True, index=True)
    especialidad = Column(String)
    curso = Column(String)
    paralelo = Column(String)
    materia = Column(String)
    profesor_id = Column(Integer, ForeignKey("profesores.id"))
    profesor = relationship("Profesor", back_populates="cursos")    

class Nota(Base):
    __tablename__ = "notas"
    id = Column(Integer, primary_key=True, index=True)
    curso_id = Column(Integer, ForeignKey("cursos.id"))
    trimestre = Column(String)  # "primero", "segundo", "tercero"
    nombre_estudiante = Column(String)
    notas = Column(String)  # JSON string de las 10 notas
    proyecto = Column(Float)
    examen = Column(Float)
    punto_extra = Column(Float)
    promedio_trimestral = Column(Float)

    curso = relationship("Curso")

Base.metadata.create_all(bind=engine)

# Esquemas
class ProfesorCreate(BaseModel):
    username: str
    password: str

class ProfesorOut(BaseModel):
    id: int
    username: str
    class Config:
        orm_mode = True

class CursoCreate(BaseModel):
    especialidad: str
    curso: str
    paralelo: str
    materia: str

class CursoOut(BaseModel):
    id: int
    especialidad: str
    curso: str
    paralelo: str
    materia: str
    class Config:
        orm_mode = True

class NotaEstudiante(BaseModel):
    nombre: str
    notas: List[Optional[float]]
    proyecto: Optional[float]
    examen: Optional[float]
    punto_extra: Optional[float]
    promedio_trimestral: float

class NotasRequest(BaseModel):
    curso_id: int
    trimestre: str  # "primero", "segundo", "tercero"
    estudiantes: List[NotaEstudiante]

# Seguridad
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Dependencias
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_profesor(authorization: str = Header(...), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer":
            raise credentials_exception
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        profesor_id: str = payload.get("sub")
        if profesor_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    profesor = db.query(Profesor).filter(Profesor.id == int(profesor_id)).first()
    if profesor is None:
        raise credentials_exception
    return profesor

# App
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Cambiar si es necesario restringir origenes
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rutas
@app.post("/register", response_model=ProfesorOut)
def register(profesor: ProfesorCreate, db: Session = Depends(get_db)):
    db_profesor = db.query(Profesor).filter(Profesor.username == profesor.username).first()
    if db_profesor:
        raise HTTPException(status_code=400, detail="Usuario ya registrado")
    hashed_pw = get_password_hash(profesor.password)
    nuevo = Profesor(username=profesor.username, hashed_password=hashed_pw)
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    return nuevo

@app.post("/login")
def login(profesor: ProfesorCreate, db: Session = Depends(get_db)):
    db_profesor = db.query(Profesor).filter(Profesor.username == profesor.username).first()
    if not db_profesor or not verify_password(profesor.password, db_profesor.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    token = create_access_token({"sub": str(db_profesor.id)})
    return {
        "access_token": token,
        "token_type": "bearer",
        "profesor_id": db_profesor.id
    }

@app.get("/")
def read_root():
    return {"message": "API funcionando"}

@app.post("/cursos", response_model=CursoOut)
def crear_curso(
    curso: CursoCreate,
    current_profesor: Profesor = Depends(get_current_profesor),
    db: Session = Depends(get_db)
):
    nuevo = Curso(
        especialidad=curso.especialidad,
        curso=curso.curso,
        paralelo=curso.paralelo,
        materia=curso.materia,
        profesor_id=current_profesor.id
    )
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    return nuevo

@app.get("/cursos", response_model=List[CursoOut])
def obtener_cursos(
    current_profesor: Profesor = Depends(get_current_profesor),
    db: Session = Depends(get_db)
):
    return db.query(Curso).filter(Curso.profesor_id == current_profesor.id).all()

@app.post("/api/notas")
def guardar_notas(
    payload: NotasRequest,
    current_profesor: Profesor = Depends(get_current_profesor),
    db: Session = Depends(get_db)
):
    print("RECIBIDO:", payload)
    # Validar curso
    curso = db.query(Curso).filter(Curso.id == payload.curso_id, Curso.profesor_id == current_profesor.id).first()
    if not curso:
        raise HTTPException(status_code=404, detail="Curso no encontrado o no autorizado")

    # Eliminar notas previas del mismo curso y trimestre para evitar duplicados
    # db.query(Nota).filter(Nota.curso_id == payload.curso_id, Nota.trimestre == payload.trimestre).delete()

    # Guardar notas
    for est in payload.estudiantes:
        nota_json = json.dumps(est.notas)

        nueva_nota = Nota(
            curso_id=payload.curso_id,
            trimestre=payload.trimestre,
            nombre_estudiante=est.nombre,
            notas=nota_json,
            proyecto=est.proyecto or 0,
            examen=est.examen or 0,
            punto_extra=est.punto_extra or 0,
            promedio_trimestral=est.promedio_trimestral
        )
        db.add(nueva_nota)

    db.commit()
    return {"msg": f"Notas del trimestre {payload.trimestre} guardadas correctamente."}


@app.get("/api/promedio-final")
def calcular_promedio_final(
    curso_id: int,
    current_profesor: Profesor = Depends(get_current_profesor),
    db: Session = Depends(get_db)
):
    trimestres = ["primer", "segundo", "tercero"]
    datos = {t: {} for t in trimestres}

    for t in trimestres:
        notas = db.query(Nota).filter(
            Nota.curso_id == curso_id,
            Nota.trimestre == t
        ).all()

        for n in notas:
            datos[t][n.nombre_estudiante] = n.promedio_trimestral

    estudiantes = set()
    for t in trimestres:
        estudiantes.update(datos[t].keys())

    resultado = []
    for nombre in sorted(estudiantes):
        p1 = datos["primer"].get(nombre)
        p2 = datos["segundo"].get(nombre)
        p3 = datos["tercero"].get(nombre)

        notas = [n for n in [p1, p2, p3] if isinstance(n, (int, float))]
        promedio = sum(notas) / len(notas) if notas else 0

        resultado.append({
            "nombre": nombre,
            "primer": p1,
            "segundo": p2,
            "tercero": p3,
            "promedio_final": promedio
        })

    return resultado
