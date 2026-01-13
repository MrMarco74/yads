from sqlmodel import SQLModel, create_engine
from yads.config import settings
from yads.models import Notification

# Ensure the model is imported so SQLModel knows about it
print("Creating database tables...")
engine = create_engine(settings.DATABASE_URL)
SQLModel.metadata.create_all(engine)
print("Done.")
