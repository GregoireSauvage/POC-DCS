from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.logging import RequestIdMiddleware
from app.api.routers import auth, films, halls, spectators, audit, health

app = FastAPI(title="Cinema DCS PoC", version="0.1.0")

# Minimal CORS for PoC (nginx is the main gateway)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RequestIdMiddleware)

app.include_router(health.router, tags=["health"])
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(films.router, prefix="/films", tags=["films"])
app.include_router(halls.router, prefix="/halls", tags=["halls"])
app.include_router(spectators.router, prefix="/spectators", tags=["spectators"])
app.include_router(audit.router, prefix="/audit", tags=["audit"])
