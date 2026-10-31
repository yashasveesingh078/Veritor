from fastapi import APIRouter

from app.api.v1 import scans

router = APIRouter(prefix="/api/v1")
router.include_router(scans.router)
