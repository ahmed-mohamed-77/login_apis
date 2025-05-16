from sqlalchemy.orm import declarative_base
from sqlalchemy import create_engine, Column, Integer, DateTime
from sqlalchemy import CheckConstraint, func, String
from dotenv import load_dotenv
import os

load_dotenv(".env", override=True)

# load engine path for psql
engine_url = os.getenv("DATABASE_URL")
engine = create_engine(url=engine_url, echo=True)


# base => to declare tables for the project
Base = declarative_base()


class User(Base):
    __tablename__ = "create_user"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    password = Column(String, nullable=False)
    status = Column(String, nullable=False, default="active")
    
    __table_args__ = (
        CheckConstraint("status IN ('active', 'not_active')", name="check_status_valid"),
    )
    
    created_at = Column(DateTime(timezone=True), default=func.now())


