"""
ShadowHawk Platform - Risk Scoring API Routes

Copyright (c) 2026 ShadowHawk Platform
Licensed under the Apache License
See LICENSE file in the project root for full license information.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
import logging

from ...domain.models.finding import Finding, FindingSeverity
from ...application.engines.risk_scoring import RiskScoringEngine

logger = logging.getLogger(__name__)

router = APIRouter()
engine = RiskScoringEngine()


class RiskRequest(BaseModel):
    title: str
    description: str
    severity: str = "medium"
    cvss_score: Optional[float] = None
    context: Optional[Dict[str, Any]] = None


@router.post("/score")
async def calculate_risk(request: RiskRequest):
    """Calculate risk score for a finding."""
    try:
        finding = Finding(
            title=request.title,
            description=request.description,
            severity=FindingSeverity(request.severity),
            cvss_score=request.cvss_score
        )
        
        risk = engine.calculate_risk(finding, context=request.context)
        
        return {
            "status": "success",
            "risk": risk.to_dict()
        }
    except Exception as e:
        logger.error(f"Risk scoring failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
