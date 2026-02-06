"""
ShadowHawk Platform - Threat Modeling API Routes

Copyright (c) 2026 ShadowHawk Platform
Licensed under the Apache License
See LICENSE file in the project root for full license information.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import logging

from ...domain.models.asset import Asset, AssetType, Criticality
from ...application.engines.threat_modeling import ThreatModelingEngine

logger = logging.getLogger(__name__)

router = APIRouter()
engine = ThreatModelingEngine()


class AssetRequest(BaseModel):
    name: str
    asset_type: str
    criticality: str
    description: str | None = None


class ThreatModelingRequest(BaseModel):
    assets: List[AssetRequest]


@router.post("/analyze")
async def analyze_threats(request: ThreatModelingRequest):
    """Analyze threats for assets."""
    try:
        assets = []
        for asset_req in request.assets:
            asset = Asset(
                name=asset_req.name,
                asset_type=AssetType(asset_req.asset_type),
                criticality=Criticality(asset_req.criticality),
                description=asset_req.description
            )
            assets.append(asset)
        
        results = {}
        for asset in assets:
            threats = engine.analyze_asset(asset)
            report = engine.generate_threat_report(asset, threats)
            results[asset.name] = report
        
        return {
            "status": "success",
            "results": results
        }
    except Exception as e:
        logger.error(f"Threat modeling failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
