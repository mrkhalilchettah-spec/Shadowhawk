"""
ShadowHawk Platform - Detection API Routes

Copyright (c) 2026 ShadowHawk Platform
Licensed under the Apache License
See LICENSE file in the project root for full license information.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import logging

from ...application.engines.detection_logic import DetectionLogicEngine

logger = logging.getLogger(__name__)

router = APIRouter()
engine = DetectionLogicEngine()


class DetectionRequest(BaseModel):
    logs: List[Dict[str, Any]]
    source: str = "unknown"


@router.post("/analyze")
async def analyze_logs(request: DetectionRequest):
    """Analyze logs for detections."""
    try:
        detections = engine.analyze_batch(request.logs, request.source)
        stats = engine.get_detection_statistics(detections)
        
        return {
            "status": "success",
            "detections": [d.to_dict() for d in detections],
            "statistics": stats
        }
    except Exception as e:
        logger.error(f"Detection analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
