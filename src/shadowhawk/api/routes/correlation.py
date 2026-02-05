"""
ShadowHawk Platform - Correlation API Routes

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import logging

from ...domain.models.detection import Detection
from ...application.engines.correlation import CorrelationEngine

logger = logging.getLogger(__name__)

router = APIRouter()
engine = CorrelationEngine()


class CorrelationRequest(BaseModel):
    detections: List[Dict[str, Any]]
    time_window_seconds: int = 300


@router.post("/analyze")
async def correlate_detections(request: CorrelationRequest):
    """Correlate security detections."""
    try:
        detections = []
        for det_data in request.detections:
            detection = Detection(
                title=det_data.get("title", ""),
                description=det_data.get("description", ""),
                source=det_data.get("source", "unknown")
            )
            detections.append(detection)
        
        report = engine.generate_correlation_report(detections)
        
        return {
            "status": "success",
            "report": report
        }
    except Exception as e:
        logger.error(f"Correlation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
