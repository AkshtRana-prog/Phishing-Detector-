import os
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, DateTime, ForeignKey, Text, text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgrespassword@localhost:5432/threat_detector"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    vector_type = Column(String, nullable=False)  # "URL", "Email", "Deepfake"
    status = Column(String, default="PENDING")    # "PENDING", "PHISHING", "SUSPICIOUS", "LEGITIMATE", "SAFE"
    severity = Column(String, default="LOW")      # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    threat_score = Column(Integer, default=0)
    target_input = Column(Text, nullable=False)
    owner_email = Column(String, default="anonymous", nullable=True)

    evidences = relationship("Evidence", back_populates="incident", cascade="all, delete-orphan")
    remediations = relationship("Remediation", back_populates="incident", cascade="all, delete-orphan")

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    key = Column(String, nullable=False)
    value = Column(Text, nullable=False)

    incident = relationship("Incident", back_populates="evidences")

class Remediation(Base):
    __tablename__ = "remediations"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    description = Column(Text, nullable=False)

    incident = relationship("Incident", back_populates="remediations")

class User(Base):
    __tablename__ = "users"

    email = Column(String, primary_key=True, index=True)
    password_hash = Column(String, nullable=False)
    status = Column(String, default="PENDING")  # "PENDING", "APPROVED"
    created_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)
    # Safely alter table to add owner_email if it doesn't exist
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE incidents ADD COLUMN owner_email VARCHAR;"))
            conn.commit()
        except Exception:
            pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
