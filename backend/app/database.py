from app.config import settings
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

db_url = settings.database_url
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

connect_args = {}
if db_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    db_url, 
    connect_args=connect_args
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
def init_db():
    from app.models import Base 
    Base.metadata.create_all(bind=engine)