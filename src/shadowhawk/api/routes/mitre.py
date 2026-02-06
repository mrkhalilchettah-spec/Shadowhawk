"""
ShadowHawk Platform - MITRE ATT&CK API Routes

Copyright (c) 2026 ShadowHawk Platform
Licensed under the Apache License
See LICENSE file in the project root for full license information.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
import logging

from ...domain.models.finding import Finding, FindingSeverity
from ...application.engines.mitre_attack import MitreAttackEngine

logger = logging.getLogger(__name__)

router = APIRouter()
engine = MitreAttackEngine()


class FindingRequest(BaseModel):
    title: str
    description: str
    severity: str = "medium"


@router.post("/map")
async def map_to_mitre(request: FindingRequest):
    """Map finding to MITRE ATT&CK framework."""
    try:
        finding = Finding(
            title=request.title,
            description=request.description,
            severity=FindingSeverity(request.severity)
        )
        
        engine.map_finding(finding)
        
        return {
            "status": "success",
            "finding": finding.to_dict()
        }
    except Exception as e:
        logger.error(f"MITRE mapping failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/technique/{technique_id}")
async def get_technique_info(technique_id: str):
    """Get information about a MITRE technique."""
    info = engine.get_technique_info(technique_id)
    if info:
        return {"status": "success", "technique": info}
    else:
        raise HTTPException(status_code=404, detail="Technique not found")
