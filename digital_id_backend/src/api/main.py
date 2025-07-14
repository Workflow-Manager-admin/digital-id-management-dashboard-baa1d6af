import os
from typing import List, Optional

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from dotenv import load_dotenv
from datetime import datetime, timedelta

# Load environment variables from .env
load_dotenv()

# FastAPI app with CORS for local frontend dev
app = FastAPI(
    title="Digital ID Backend API",
    description="APIs for admin login, user management, digital IDs, and number linking.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Auth", "description": "Admin JWT authentication"},
        {"name": "Users", "description": "User/Holder management"},
        {"name": "Digital IDs", "description": "Digital ID profile management"},
        {"name": "Unique Numbers", "description": "Unique number management"},
        {"name": "Linking", "description": "Link unique number to Digital ID"},
    ],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQLALCHEMY DATABASE SETUP
DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_HOST = os.getenv("POSTGRES_URL")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DB")
SQLALCHEMY_DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# PASSWORD HASHING & JWT
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
SECRET_KEY = os.getenv("SECRET_KEY", "change_this_to_a_long_random_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

# ----- MODELS -----
# SQLAlchemy models (mirror digital_id_db schema)
class Admin(Base):
    __tablename__ = "admin"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    digital_id_profile = relationship("DigitalIDProfile", uselist=False, back_populates="user")

class DigitalIDProfile(Base):
    __tablename__ = "digital_id_profiles"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    id_number = Column(String, unique=True, nullable=False)
    issue_date = Column(String)  # ISO date string
    user = relationship("User", back_populates="digital_id_profile")
    unique_number_link = relationship("UniqueNumber", uselist=False, back_populates="linked_profile")

class UniqueNumber(Base):
    __tablename__ = "unique_numbers"
    id = Column(Integer, primary_key=True, index=True)
    number = Column(String, unique=True, nullable=False)
    profile_id = Column(Integer, ForeignKey("digital_id_profiles.id", ondelete="SET NULL"), nullable=True)
    status = Column(String, default="unlinked")  # "unlinked", "linked"
    linked_profile = relationship("DigitalIDProfile", back_populates="unique_number_link")

# ----- Pydantic Schemas -----
# Auth
class Token(BaseModel):
    """JWT access token model."""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(..., description="Type: bearer")

class TokenData(BaseModel):
    username: Optional[str] = None

class AdminLoginRequest(BaseModel):
    username: str = Field(..., description="Admin username")
    password: str = Field(..., description="Admin password")

# Users
class UserBase(BaseModel):
    full_name: str = Field(..., description="Full name of user")
    email: str = Field(..., description="Email address")

class UserCreate(UserBase):
    pass

class UserRead(UserBase):
    id: int

    class Config:
        from_attributes = True

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None

# Digital IDs
class DigitalIDProfileBase(BaseModel):
    id_number: str = Field(..., description="Digital ID number (unique)")
    issue_date: Optional[str] = Field(None, description="Issue date (ISO format)")

class DigitalIDProfileCreate(DigitalIDProfileBase):
    user_id: int

class DigitalIDProfileRead(DigitalIDProfileBase):
    id: int
    user_id: int

    class Config:
        from_attributes = True

class DigitalIDProfileUpdate(BaseModel):
    id_number: Optional[str] = None
    issue_date: Optional[str] = None

# Unique Numbers
class UniqueNumberRead(BaseModel):
    id: int
    number: str
    status: str
    profile_id: Optional[int]

    class Config:
        from_attributes = True

# Linking
class LinkNumberRequest(BaseModel):
    unique_number_id: int = Field(..., description="ID of unique number")
    digital_id_profile_id: int = Field(..., description="ID of digital ID profile")

class LinkNumberResult(BaseModel):
    unique_number_id: int
    linked_profile_id: int

# ----- UTILITY FUNCTIONS -----
def get_db():
    """FastAPI dependency: yields SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Hash a password."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_admin_by_username(db: Session, username: str):
    """Fetch admin by username."""
    return db.query(Admin).filter(Admin.username == username).first()

def authenticate_admin(db: Session, username: str, password: str):
    """Verify admin user's credentials."""
    admin = get_admin_by_username(db, username)
    if admin and verify_password(password, admin.hashed_password):
        return admin
    return None

async def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Dependency: checks admin JWT and returns admin object."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    admin = get_admin_by_username(db, token_data.username)
    if admin is None:
        raise credentials_exception
    return admin

# ----- ROUTES -----
@app.get("/", tags=["Health"])
def health_check():
    """Health check for service."""
    return {"status": "Healthy"}

# PUBLIC_INTERFACE
@app.post("/login", response_model=Token, tags=["Auth"], summary="Admin login")
def admin_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Authenticate admin and return JWT token.

    - **username**: admin username
    - **password**: admin password
    """
    admin = authenticate_admin(db, form_data.username, form_data.password)
    if not admin:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": admin.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- USER CRUD ---
# PUBLIC_INTERFACE
@app.post("/users", response_model=UserRead, tags=["Users"], summary="Create user/holder", dependencies=[Depends(get_current_admin)])
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """Create a new user/holder."""
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = User(full_name=user.full_name, email=user.email)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# PUBLIC_INTERFACE
@app.get("/users", response_model=List[UserRead], tags=["Users"], summary="List users", dependencies=[Depends(get_current_admin)])
def list_users(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """List all users."""
    return db.query(User).offset(skip).limit(limit).all()

# PUBLIC_INTERFACE
@app.get("/users/{user_id}", response_model=UserRead, tags=["Users"], summary="Get user info", dependencies=[Depends(get_current_admin)])
def get_user(user_id: int, db: Session = Depends(get_db)):
    """Get info for a user/holder."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# PUBLIC_INTERFACE
@app.patch("/users/{user_id}", response_model=UserRead, tags=["Users"], summary="Update user", dependencies=[Depends(get_current_admin)])
def update_user(user_id: int, user_in: UserUpdate, db: Session = Depends(get_db)):
    """Update a user's information."""
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    if user_in.email:
        conflict = db.query(User).filter(User.email == user_in.email, User.id != user_id).first()
        if conflict:
            raise HTTPException(status_code=400, detail="Email already in use")
        db_user.email = user_in.email
    if user_in.full_name:
        db_user.full_name = user_in.full_name
    db.commit()
    db.refresh(db_user)
    return db_user

# PUBLIC_INTERFACE
@app.delete("/users/{user_id}", tags=["Users"], summary="Delete user", dependencies=[Depends(get_current_admin)])
def delete_user(user_id: int, db: Session = Depends(get_db)):
    """Delete a user and any related digital ID profile."""
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return {"detail": "User deleted"}

# --- DIGITAL ID CRUD ---
# PUBLIC_INTERFACE
@app.post("/digital_ids", response_model=DigitalIDProfileRead, tags=["Digital IDs"], summary="Create digital ID profile", dependencies=[Depends(get_current_admin)])
def create_digital_id(profile: DigitalIDProfileCreate, db: Session = Depends(get_db)):
    """Create a digital ID profile for a user."""
    # Ensure user exists
    user = db.query(User).filter(User.id == profile.user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="User does not exist")
    # Ensure user does not already have a profile
    if db.query(DigitalIDProfile).filter(DigitalIDProfile.user_id == profile.user_id).first():
        raise HTTPException(status_code=400, detail="User already has a digital ID profile")
    # Ensure unique id_number
    if db.query(DigitalIDProfile).filter(DigitalIDProfile.id_number == profile.id_number).first():
        raise HTTPException(status_code=400, detail="ID number already in use")
    digital_profile = DigitalIDProfile(
        user_id=profile.user_id,
        id_number=profile.id_number,
        issue_date=profile.issue_date
    )
    db.add(digital_profile)
    db.commit()
    db.refresh(digital_profile)
    return digital_profile

# PUBLIC_INTERFACE
@app.get("/digital_ids", response_model=List[DigitalIDProfileRead], tags=["Digital IDs"], summary="List digital IDs", dependencies=[Depends(get_current_admin)])
def list_digital_ids(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """List all digital ID profiles."""
    return db.query(DigitalIDProfile).offset(skip).limit(limit).all()

# PUBLIC_INTERFACE
@app.get("/digital_ids/{profile_id}", response_model=DigitalIDProfileRead, tags=["Digital IDs"], summary="Get digital ID", dependencies=[Depends(get_current_admin)])
def get_digital_id(profile_id: int, db: Session = Depends(get_db)):
    """Get a digital ID profile by id."""
    profile = db.query(DigitalIDProfile).filter(DigitalIDProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Digital ID profile not found")
    return profile

# PUBLIC_INTERFACE
@app.patch("/digital_ids/{profile_id}", response_model=DigitalIDProfileRead, tags=["Digital IDs"], summary="Update digital ID", dependencies=[Depends(get_current_admin)])
def update_digital_id(profile_id: int, profile_in: DigitalIDProfileUpdate, db: Session = Depends(get_db)):
    """Update digital ID profile information."""
    profile = db.query(DigitalIDProfile).filter(DigitalIDProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Digital ID profile not found")
    if profile_in.id_number:
        conflict = db.query(DigitalIDProfile).filter(
            DigitalIDProfile.id_number == profile_in.id_number,
            DigitalIDProfile.id != profile_id
        ).first()
        if conflict:
            raise HTTPException(status_code=400, detail="ID number already in use")
        profile.id_number = profile_in.id_number
    if profile_in.issue_date:
        profile.issue_date = profile_in.issue_date
    db.commit()
    db.refresh(profile)
    return profile

# PUBLIC_INTERFACE
@app.delete("/digital_ids/{profile_id}", tags=["Digital IDs"], summary="Delete digital ID", dependencies=[Depends(get_current_admin)])
def delete_digital_id(profile_id: int, db: Session = Depends(get_db)):
    """Delete a digital ID profile."""
    profile = db.query(DigitalIDProfile).filter(DigitalIDProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Digital ID profile not found")
    db.delete(profile)
    db.commit()
    return {"detail": "Digital ID deleted"}

# --- UNIQUE NUMBER LIST ---
# PUBLIC_INTERFACE
@app.get("/unique_numbers", response_model=List[UniqueNumberRead], tags=["Unique Numbers"], summary="List unique numbers", dependencies=[Depends(get_current_admin)])
def list_unique_numbers(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    List unique numbers and their linking status.
    - "status": "linked" (associated), "unlinked" (not in use)
    """
    return db.query(UniqueNumber).offset(skip).limit(limit).all()

# --- LINKING LOGIC ---
# PUBLIC_INTERFACE
@app.post("/link_number", response_model=LinkNumberResult, tags=["Linking"], summary="Link a unique number to digital ID", dependencies=[Depends(get_current_admin)])
def link_unique_number(req: LinkNumberRequest, db: Session = Depends(get_db)):
    """
    Link a unique number to a digital ID profile (each can link only once).

    - Sets unique_number's status to 'linked'
    - Only allows linking if both exist, and both are unlinked/not linked elsewhere
    """
    number = db.query(UniqueNumber).filter(UniqueNumber.id == req.unique_number_id).first()
    profile = db.query(DigitalIDProfile).filter(DigitalIDProfile.id == req.digital_id_profile_id).first()

    if number is None or profile is None:
        raise HTTPException(status_code=400, detail="Invalid unique number or digital ID profile")

    if number.status == "linked":
        raise HTTPException(status_code=400, detail="Number already linked")

    if number.profile_id is not None:
        raise HTTPException(status_code=400, detail="Number already linked to a profile")

    # Only one unique number per digital_id_profile
    already_linked = db.query(UniqueNumber).filter(UniqueNumber.profile_id == profile.id).first()
    if already_linked:
        raise HTTPException(status_code=400, detail="Profile already linked to a unique number")

    number.profile_id = profile.id
    number.status = "linked"
    db.commit()
    return LinkNumberResult(unique_number_id=number.id, linked_profile_id=profile.id)

# --- UNLINKING LOGIC ---
# PUBLIC_INTERFACE
@app.post("/unlink_number/{unique_number_id}", tags=["Linking"], summary="Unlink a unique number", dependencies=[Depends(get_current_admin)])
def unlink_unique_number(unique_number_id: int, db: Session = Depends(get_db)):
    """Unlink the unique number from its digital ID profile (if any)."""
    number = db.query(UniqueNumber).filter(UniqueNumber.id == unique_number_id).first()
    if number is None:
        raise HTTPException(status_code=404, detail="Unique number not found")
    if number.status != "linked":
        raise HTTPException(status_code=400, detail="Number is not linked")
    number.status = "unlinked"
    number.profile_id = None
    db.commit()
    return {"detail": "Unique number unlinked"}

# ----- EXCEPTION HANDLERS -----
@app.exception_handler(HTTPException)
def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

# Swagger/OpenAPI enhancement
@app.get("/docs/websocket_help", tags=["Health"])
def websocket_usage_help():
    """
    Usage notes for WebSocket (N/A - only REST endpoints implemented).
    """
    return {"detail": "No WebSocket endpoints for this backend. Use RESTful APIs documented in /docs."}

# ----- INITIALIZE TABLES (for development only) -----
# Run once manually, or via alembic for migrations in real scenario.
if os.environ.get("RUN_DB_INIT", "0") == "1":
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
