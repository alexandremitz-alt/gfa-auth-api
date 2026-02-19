from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import bcrypt
import jwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MySQL connection
MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
MYSQL_DATABASE = os.environ.get('MYSQL_DATABASE', 'gfa_auth')

DATABASE_URL = f"mysql+mysqlconnector://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DATABASE}"

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=3600)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT Config
JWT_SECRET = os.environ.get('JWT_SECRET', 'gfa-unified-admin-secret-key-2024')
JWT_ALGORITHM = "HS256"

# Create the main app
app = FastAPI(title="GFA Unified Admin API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== DATABASE MODELS ====================

class UserDB(Base):
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    nome = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    senha = Column(String(255), nullable=False)
    telefone = Column(String(50), nullable=False)
    cargo = Column(String(50), nullable=False)
    sistemas = Column(JSON, nullable=False, default={})
    ativo = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class ActivityLogDB(Base):
    __tablename__ = "activity_logs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), nullable=False)
    user_nome = Column(String(255), nullable=False)
    action = Column(String(50), nullable=False)
    details = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    ip_address = Column(String(50), nullable=True)

class SystemDB(Base):
    __tablename__ = "systems"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    nome = Column(String(255), nullable=False)
    tag = Column(String(50), unique=True, nullable=False)
    cor = Column(String(20), nullable=False, default="#0066CC")
    ativo = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

# Create tables
Base.metadata.create_all(bind=engine)

# ==================== PYDANTIC MODELS ====================

class SystemAccess(BaseModel):
    pass  # Dynamic based on registered systems

class UserBase(BaseModel):
    nome: str
    email: EmailStr
    telefone: str
    cargo: str
    sistemas: dict = {}
    ativo: bool = True

class UserCreate(UserBase):
    senha: str

class UserUpdate(BaseModel):
    nome: Optional[str] = None
    email: Optional[EmailStr] = None
    telefone: Optional[str] = None
    cargo: Optional[str] = None
    sistemas: Optional[dict] = None
    ativo: Optional[bool] = None

class UserResponse(UserBase):
    id: str
    created_at: str
    updated_at: str

class UserPasswordUpdate(BaseModel):
    nova_senha: str

class LoginRequest(BaseModel):
    email: EmailStr
    senha: str

class LoginResponse(BaseModel):
    token: str
    user: UserResponse

class ActivityLogResponse(BaseModel):
    id: str
    user_id: str
    user_nome: str
    action: str
    details: str
    timestamp: str
    ip_address: Optional[str] = None

class StatsResponse(BaseModel):
    total_users: int
    active_users: int
    inactive_users: int
    by_cargo: dict
    by_sistema: dict
    recent_activity: int

class SystemBase(BaseModel):
    nome: str
    tag: str
    cor: str = "#0066CC"
    ativo: bool = True

class SystemCreate(SystemBase):
    pass

class SystemUpdate(BaseModel):
    nome: Optional[str] = None
    tag: Optional[str] = None
    cor: Optional[str] = None
    ativo: Optional[bool] = None

class SystemResponse(SystemBase):
    id: str
    created_at: str
    updated_at: str

# ==================== DEPENDENCIES ====================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==================== HELPERS ====================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, email: str, cargo: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "cargo": cargo,
        "exp": datetime.now(timezone.utc).timestamp() + 86400
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = db.query(UserDB).filter(UserDB.id == payload["user_id"]).first()
        if not user:
            raise HTTPException(status_code=401, detail="Usuário não encontrado")
        if user.cargo != "administrador":
            raise HTTPException(status_code=403, detail="Acesso restrito a administradores")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

def log_activity(db: Session, user_id: str, user_nome: str, action: str, details: str, ip: str = None):
    log = ActivityLogDB(
        id=str(uuid.uuid4()),
        user_id=user_id,
        user_nome=user_nome,
        action=action,
        details=details,
        timestamp=datetime.now(timezone.utc),
        ip_address=ip
    )
    db.add(log)
    db.commit()

def user_to_response(user: UserDB) -> UserResponse:
    return UserResponse(
        id=user.id,
        nome=user.nome,
        email=user.email,
        telefone=user.telefone,
        cargo=user.cargo,
        sistemas=user.sistemas or {},
        ativo=user.ativo,
        created_at=user.created_at.isoformat() if user.created_at else "",
        updated_at=user.updated_at.isoformat() if user.updated_at else ""
    )

def system_to_response(system: SystemDB) -> SystemResponse:
    return SystemResponse(
        id=system.id,
        nome=system.nome,
        tag=system.tag,
        cor=system.cor,
        ativo=system.ativo,
        created_at=system.created_at.isoformat() if system.created_at else "",
        updated_at=system.updated_at.isoformat() if system.updated_at else ""
    )

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/login", response_model=LoginResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.email == request.email).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    
    if not verify_password(request.senha, user.senha):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    
    if not user.ativo:
        raise HTTPException(status_code=401, detail="Usuário inativo")
    
    if user.cargo != "administrador":
        raise HTTPException(status_code=403, detail="Acesso restrito a administradores")
    
    token = create_token(user.id, user.email, user.cargo)
    
    log_activity(db, user.id, user.nome, "login", "Login realizado com sucesso")
    
    return LoginResponse(token=token, user=user_to_response(user))

@api_router.get("/auth/me", response_model=UserResponse)
def get_me(current_user: UserDB = Depends(get_current_user)):
    return user_to_response(current_user)

# ==================== USER ROUTES ====================

@api_router.get("/users", response_model=List[UserResponse])
def get_users(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.query(UserDB).all()
    return [user_to_response(u) for u in users]

@api_router.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return user_to_response(user)

@api_router.post("/users", response_model=UserResponse, status_code=201)
def create_user(user: UserCreate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    existing = db.query(UserDB).filter(UserDB.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    
    now = datetime.now(timezone.utc)
    db_user = UserDB(
        id=str(uuid.uuid4()),
        nome=user.nome,
        email=user.email,
        telefone=user.telefone,
        cargo=user.cargo,
        sistemas=user.sistemas,
        ativo=user.ativo,
        senha=hash_password(user.senha),
        created_at=now,
        updated_at=now
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    log_activity(db, current_user.id, current_user.nome, "create_user", f"Usuário {user.nome} ({user.email}) criado")
    
    return user_to_response(db_user)

@api_router.put("/users/{user_id}", response_model=UserResponse)
def update_user(user_id: str, user_update: UserUpdate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    if user_update.nome is not None:
        user.nome = user_update.nome
    if user_update.email is not None:
        existing = db.query(UserDB).filter(UserDB.email == user_update.email, UserDB.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email já cadastrado")
        user.email = user_update.email
    if user_update.telefone is not None:
        user.telefone = user_update.telefone
    if user_update.cargo is not None:
        user.cargo = user_update.cargo
    if user_update.sistemas is not None:
        user.sistemas = user_update.sistemas
    if user_update.ativo is not None:
        user.ativo = user_update.ativo
    
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    
    log_activity(db, current_user.id, current_user.nome, "update_user", f"Usuário {user.nome} atualizado")
    
    return user_to_response(user)

@api_router.delete("/users/{user_id}")
def delete_user(user_id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Não é possível excluir seu próprio usuário")
    
    user_nome = user.nome
    user_email = user.email
    
    db.delete(user)
    db.commit()
    
    log_activity(db, current_user.id, current_user.nome, "delete_user", f"Usuário {user_nome} ({user_email}) excluído")
    
    return {"message": "Usuário excluído com sucesso"}

@api_router.put("/users/{user_id}/password")
def change_password(user_id: str, password_update: UserPasswordUpdate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    user.senha = hash_password(password_update.nova_senha)
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    log_activity(db, current_user.id, current_user.nome, "change_password", f"Senha do usuário {user.nome} alterada")
    
    return {"message": "Senha alterada com sucesso"}

# ==================== SYSTEMS ROUTES ====================

@api_router.get("/systems", response_model=List[SystemResponse])
def get_systems(db: Session = Depends(get_db)):
    systems = db.query(SystemDB).all()
    return [system_to_response(s) for s in systems]

@api_router.get("/systems/active", response_model=List[SystemResponse])
def get_active_systems(db: Session = Depends(get_db)):
    systems = db.query(SystemDB).filter(SystemDB.ativo == True).all()
    return [system_to_response(s) for s in systems]

@api_router.get("/systems/{system_id}", response_model=SystemResponse)
def get_system(system_id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    system = db.query(SystemDB).filter(SystemDB.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="Sistema não encontrado")
    return system_to_response(system)

@api_router.post("/systems", response_model=SystemResponse, status_code=201)
def create_system(system: SystemCreate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    existing = db.query(SystemDB).filter(SystemDB.tag == system.tag).first()
    if existing:
        raise HTTPException(status_code=400, detail="Tag já cadastrada")
    
    now = datetime.now(timezone.utc)
    db_system = SystemDB(
        id=str(uuid.uuid4()),
        nome=system.nome,
        tag=system.tag,
        cor=system.cor,
        ativo=system.ativo,
        created_at=now,
        updated_at=now
    )
    
    db.add(db_system)
    db.commit()
    db.refresh(db_system)
    
    log_activity(db, current_user.id, current_user.nome, "create_system", f"Sistema {system.nome} ({system.tag}) criado")
    
    return system_to_response(db_system)

@api_router.put("/systems/{system_id}", response_model=SystemResponse)
def update_system(system_id: str, system_update: SystemUpdate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    system = db.query(SystemDB).filter(SystemDB.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="Sistema não encontrado")
    
    if system_update.nome is not None:
        system.nome = system_update.nome
    if system_update.tag is not None:
        existing = db.query(SystemDB).filter(SystemDB.tag == system_update.tag, SystemDB.id != system_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Tag já cadastrada")
        system.tag = system_update.tag
    if system_update.cor is not None:
        system.cor = system_update.cor
    if system_update.ativo is not None:
        system.ativo = system_update.ativo
    
    system.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(system)
    
    log_activity(db, current_user.id, current_user.nome, "update_system", f"Sistema {system.nome} atualizado")
    
    return system_to_response(system)

@api_router.delete("/systems/{system_id}")
def delete_system(system_id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    system = db.query(SystemDB).filter(SystemDB.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="Sistema não encontrado")
    
    system_nome = system.nome
    system_tag = system.tag
    
    db.delete(system)
    db.commit()
    
    log_activity(db, current_user.id, current_user.nome, "delete_system", f"Sistema {system_nome} ({system_tag}) excluído")
    
    return {"message": "Sistema excluído com sucesso"}

# ==================== ACTIVITY LOGS ROUTES ====================

@api_router.get("/activity-logs", response_model=List[ActivityLogResponse])
def get_activity_logs(limit: int = 50, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    logs = db.query(ActivityLogDB).order_by(ActivityLogDB.timestamp.desc()).limit(limit).all()
    return [ActivityLogResponse(
        id=log.id,
        user_id=log.user_id,
        user_nome=log.user_nome,
        action=log.action,
        details=log.details,
        timestamp=log.timestamp.isoformat() if log.timestamp else "",
        ip_address=log.ip_address
    ) for log in logs]

# ==================== STATS ROUTES ====================

@api_router.get("/stats", response_model=StatsResponse)
def get_stats(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.query(UserDB).all()
    systems = db.query(SystemDB).filter(SystemDB.ativo == True).all()
    
    total = len(users)
    active = len([u for u in users if u.ativo])
    inactive = total - active
    
    by_cargo = {}
    for u in users:
        cargo = u.cargo or "outros"
        by_cargo[cargo] = by_cargo.get(cargo, 0) + 1
    
    by_sistema = {}
    for s in systems:
        by_sistema[s.tag] = 0
    
    for u in users:
        sistemas = u.sistemas or {}
        for tag in sistemas:
            if sistemas.get(tag) and tag in by_sistema:
                by_sistema[tag] += 1
    
    from datetime import timedelta
    yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_logs = db.query(ActivityLogDB).filter(ActivityLogDB.timestamp >= yesterday).count()
    
    return StatsResponse(
        total_users=total,
        active_users=active,
        inactive_users=inactive,
        by_cargo=by_cargo,
        by_sistema=by_sistema,
        recent_activity=recent_logs
    )

# ==================== SEED ADMIN ====================

@api_router.post("/seed-admin")
def seed_admin(db: Session = Depends(get_db)):
    admin_exists = db.query(UserDB).filter(UserDB.cargo == "administrador").first()
    if admin_exists:
        return {"message": "Admin já existe", "email": admin_exists.email}
    
    now = datetime.now(timezone.utc)
    admin = UserDB(
        id=str(uuid.uuid4()),
        nome="Administrador",
        email="admin@gfa.com",
        telefone="(00) 00000-0000",
        cargo="administrador",
        sistemas={},
        ativo=True,
        senha=hash_password("admin123"),
        created_at=now,
        updated_at=now
    )
    db.add(admin)
    db.commit()
    return {"message": "Admin criado", "email": "admin@gfa.com", "senha": "admin123"}

# ==================== SEED DEFAULT SYSTEMS ====================

@api_router.post("/seed-systems")
def seed_systems(db: Session = Depends(get_db)):
    default_systems = [
        {"nome": "Orçamentos", "tag": "orcamentos", "cor": "#f59e0b"},
        {"nome": "Veículos", "tag": "veiculos", "cor": "#22c55e"},
        {"nome": "Ordem de Serviço", "tag": "ordem_servico", "cor": "#8b5cf6"},
        {"nome": "FTTH", "tag": "ftth", "cor": "#0ea5e9"},
    ]
    
    created = []
    for sys in default_systems:
        existing = db.query(SystemDB).filter(SystemDB.tag == sys["tag"]).first()
        if not existing:
            now = datetime.now(timezone.utc)
            db_system = SystemDB(
                id=str(uuid.uuid4()),
                nome=sys["nome"],
                tag=sys["tag"],
                cor=sys["cor"],
                ativo=True,
                created_at=now,
                updated_at=now
            )
            db.add(db_system)
            created.append(sys["nome"])
    
    db.commit()
    return {"message": f"Sistemas criados: {', '.join(created) if created else 'Nenhum (já existiam)'}"}

# ==================== EXTERNAL AUTH API ====================

@api_router.post("/auth/validate")
def validate_user_for_system(request: LoginRequest, sistema: str, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.email == request.email).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    
    if not verify_password(request.senha, user.senha):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    
    if not user.ativo:
        raise HTTPException(status_code=401, detail="Usuário inativo")
    
    sistemas = user.sistemas or {}
    if not sistemas.get(sistema, False):
        raise HTTPException(status_code=403, detail=f"Usuário sem acesso ao sistema {sistema}")
    
    return {
        "valid": True,
        "user": {
            "id": user.id,
            "nome": user.nome,
            "email": user.email,
            "cargo": user.cargo
        }
    }

# ==================== ROOT ====================

@api_router.get("/")
def root():
    return {"message": "GFA Unified Admin API", "version": "1.0.0"}

# Include router and middleware
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)
