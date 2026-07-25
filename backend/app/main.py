from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import router as api_router
from app.api.auth import router as auth_router
from app.core.config import settings
from app.db.database import init_db

# Initialize database (creates tables + seeds default admin)
init_db()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Backend API for CNN-LSTM based IDS for LLM Applications",
    version="1.0.0",
)

# Allow Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(api_router,  prefix=settings.API_V1_STR)
app.include_router(auth_router, prefix=settings.API_V1_STR)

@app.get("/")
def read_root():
    return {"message": "Welcome to the LLM IDS API"}
