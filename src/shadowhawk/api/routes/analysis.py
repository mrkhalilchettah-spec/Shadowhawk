"""
ShadowHawk Platform - AI Analysis API Routes

Copyright (c) 2026 ShadowHawk Platform
Licensed under the Apache License
See LICENSE file in the project root for full license information.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import logging

from ...domain.models.finding import Finding, FindingSeverity
from ...application.engines.ai_analysis import AIAnalysisEngine

logger = logging.getLogger(__name__)

router = APIRouter()
engine = AIAnalysisEngine()


class AnalysisRequest(BaseModel):
    title: str
    description: str
    severity: str = "medium"
    cvss_score: float | None = None


@router.post("/explain")
async def explain_finding(request: AnalysisRequest):
    """Get AI-powered explanation for a finding."""
    try:
        finding = Finding(
            title=request.title,
            description=request.description,
            severity=FindingSeverity(request.severity),
            cvss_score=request.cvss_score
        )
        
        explanation = engine.explain_finding(finding)
        
        return {
            "status": "success",
            "explanation": explanation
        }
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
