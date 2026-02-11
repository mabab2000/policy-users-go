from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import os

from routes import router
from database import engine
from models import Base

# Create database tables
Base.metadata.create_all(bind=engine)

# Create FastAPI app
app = FastAPI(
    title="Policy Users API",
    description="API for managing users, projects, and policies",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api")

# Serve OpenAPI YAML and Swagger UI
@app.get("/swagger.yaml")
async def get_openapi_yaml():
    return FileResponse("docs/openapi.yaml")

@app.get("/swagger")
async def get_swagger():
    return FileResponse("templates/swagger.html")

# Health check
@app.get("/health")
async def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)