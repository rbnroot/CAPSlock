"""
CAPSlock Web API
FastAPI backend for CAPSlock Conditional Access analysis tool
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import uvicorn

from CAPSlock.db import get_session, DB_PATH
from CAPSlock.models import SignInContext
from CAPSlock.query import get_policy_results_for_user
from CAPSlock.analyze import analyze
from CAPSlock.serializers import (
    categorize_get_policies_results,
    categorize_what_if_results,
    serialize_policy_results,
)
from CAPSlock.normalize import normalize_bool_str, normalize_unknown_str


app = FastAPI(
    title="CAPSlock API",
    description="Conditional Access Policy Analysis API",
    version="1.0.0",
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic models for request/response
class WhatIfRequest(BaseModel):
    user: str = Field(..., description="User Principal Name")
    resource: Optional[str] = Field(None, description="Resource/App ID")
    acr: Optional[str] = Field(None, description="Authentication Context Class Reference")
    trusted_location: Optional[bool] = Field(None, description="Trusted location flag")
    platform: Optional[str] = Field(None, description="Device platform")
    client_app: Optional[str] = Field(None, description="Client app type")
    signin_risk: Optional[str] = Field(None, description="Sign-in risk level")
    user_risk: Optional[str] = Field(None, description="User risk level")
    auth_flow: Optional[str] = Field(None, description="Authentication flow")
    device_filter: Optional[bool] = Field(None, description="Device filter match flag")
    device_compliant: Optional[bool] = Field(None, description="Device compliance flag")
    device_hybrid_joined: Optional[bool] = Field(None, description="Device hybrid joined flag")
    db_path: Optional[str] = Field(DB_PATH, description="Path to roadrecon.db")


class AnalyzeRequest(BaseModel):
    user: str = Field(..., description="User Principal Name")
    resource: Optional[str] = Field(None, description="Resource/App ID")
    acr: Optional[str] = Field(None, description="Authentication Context Class Reference")
    trusted_location: Optional[bool] = Field(None, description="Fixed trusted location (permuted if not provided)")
    platform: Optional[str] = Field(None, description="Fixed platform (permuted if not provided)")
    client_app: Optional[str] = Field(None, description="Fixed client app (permuted if not provided)")
    signin_risk: Optional[str] = Field(None, description="Fixed sign-in risk (permuted if not provided)")
    user_risk: Optional[str] = Field(None, description="Fixed user risk (permuted if not provided)")
    auth_flow: Optional[str] = Field(None, description="Fixed auth flow (permuted if not provided)")
    device_filter: Optional[bool] = Field(None, description="Fixed device filter (permuted if not provided)")
    device_compliant: Optional[bool] = Field(None, description="Device compliance flag")
    device_hybrid_joined: Optional[bool] = Field(None, description="Device hybrid joined flag")
    max_scenarios: int = Field(1000, description="Maximum scenarios to evaluate")
    db_path: Optional[str] = Field(DB_PATH, description="Path to roadrecon.db")


@app.get("/")
async def root():
    """Serve the main HTML page"""
    return FileResponse("static/index.html")


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "CAPSlock API"}


@app.get("/api/all-policies")
async def get_all_policies(
    db_path: str = Query(DB_PATH, description="Path to roadrecon.db"),
):
    """
    Get all Conditional Access policies in the tenant
    """
    try:
        from CAPSlock.db import load_capolicies, parse_policy_details

        session = get_session(db_path)
        policies = load_capolicies(session)

        result = []
        for policy in policies:
            details = parse_policy_details(policy)
            for detail in details:
                result.append({
                    "policy_id": policy.objectId,
                    "policy_name": policy.displayName,
                    "state": detail.get("State", "Unknown"),
                    "created": detail.get("CreatedDateTime"),
                    "modified": detail.get("ModifiedDateTime"),
                    "detail": detail
                })

        session.close()
        return {
            "total": len(result),
            "policies": result
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/policies")
async def get_policies(
    user: str = Query(..., description="User Principal Name"),
    app: Optional[str] = Query(None, description="Application ID filter"),
    results: str = Query("applied", description="Results mode: applied, exclusions, or all"),
    db_path: str = Query(DB_PATH, description="Path to roadrecon.db"),
):
    """
    Get Conditional Access policies that apply to a user
    """
    try:
        session = get_session(db_path)
        signin_ctx = SignInContext(app_id=app)

        policy_results = get_policy_results_for_user(
            session=session,
            user_upn=user.strip().lower(),
            signin_ctx=signin_ctx,
            mode="get-policies",
        )

        categorized = categorize_get_policies_results(policy_results)

        # Filter based on results mode
        if results == "applied":
            response = {
                "user": user,
                "results_mode": results,
                "policies": categorized["applied"],
                "count": categorized["applied_count"],
            }
        elif results == "exclusions":
            response = {
                "user": user,
                "results_mode": results,
                "policies": categorized["excluded"],
                "count": categorized["excluded_count"],
            }
        else:  # all
            response = {
                "user": user,
                "results_mode": results,
                "applied": categorized["applied"],
                "excluded": categorized["excluded"],
                "not_included": categorized["not_included"],
                "counts": {
                    "applied": categorized["applied_count"],
                    "excluded": categorized["excluded_count"],
                    "not_included": categorized["not_included_count"],
                    "total": categorized["total_policies"],
                },
            }

        session.close()
        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/what-if")
async def what_if(request: WhatIfRequest):
    """
    Evaluate policies for a hypothetical sign-in scenario
    """
    try:
        # Validate resource vs acr
        if request.resource and request.acr:
            raise HTTPException(
                status_code=400,
                detail="resource and acr are mutually exclusive (choose one)",
            )

        session = get_session(request.db_path)

        signin_ctx = SignInContext(
            app_id=normalize_unknown_str(request.resource),
            acr=normalize_unknown_str(request.acr),
            trusted_location=request.trusted_location,
            platform=(request.platform.lower() if request.platform else None),
            client_app=request.client_app,
            signin_risk=(request.signin_risk.lower() if request.signin_risk else None),
            user_risk=(request.user_risk.lower() if request.user_risk else None),
            auth_flow=(request.auth_flow.lower() if request.auth_flow else None),
            device_filter=request.device_filter,
            device_hybrid_joined=request.device_hybrid_joined,
            device_compliant=request.device_compliant,
        )

        policy_results = get_policy_results_for_user(
            session=session,
            user_upn=request.user.strip().lower(),
            signin_ctx=signin_ctx,
            mode="what-if",
        )

        categorized = categorize_what_if_results(policy_results)

        response = {
            "user": request.user,
            "scenario": {
                "resource": signin_ctx.app_id,
                "acr": signin_ctx.acr,
                "trusted_location": signin_ctx.trusted_location,
                "platform": signin_ctx.platform,
                "client_app": signin_ctx.client_app,
                "signin_risk": signin_ctx.signin_risk,
                "user_risk": signin_ctx.user_risk,
                "auth_flow": signin_ctx.auth_flow,
                "device_filter": signin_ctx.device_filter,
            },
            "applied_definitive": categorized["applied_definitive"],
            "applied_signal_dependent": categorized["applied_signal_dependent"],
            "counts": {
                "total": categorized["total_policies"],
                "applied": categorized["applied_count"],
                "definitive": categorized["definitive_count"],
                "signal_dependent": categorized["signal_dependent_count"],
            },
        }

        session.close()
        return response

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze")
async def analyze_gaps(request: AnalyzeRequest):
    """
    Analyze Conditional Access gaps by permuting sign-in scenarios
    """
    try:
        # Validate resource vs acr
        if request.resource and request.acr:
            raise HTTPException(
                status_code=400,
                detail="resource and acr are mutually exclusive (choose one)",
            )
        if not request.resource and not request.acr:
            raise HTTPException(
                status_code=400,
                detail="You must provide either resource or acr",
            )

        session = get_session(request.db_path)

        base = SignInContext(
            app_id=normalize_unknown_str(request.resource),
            acr=normalize_unknown_str(request.acr),
            trusted_location=None,
            platform=None,
            client_app=None,
            signin_risk=None,
            user_risk=None,
            auth_flow=None,
            device_filter=None,
            device_hybrid_joined=request.device_hybrid_joined,
            device_compliant=request.device_compliant,
        )

        fixed = {
            "trusted_location": request.trusted_location,
            "platform": (request.platform.lower() if request.platform else None),
            "client_app": request.client_app,
            "signin_risk": (request.signin_risk.lower() if request.signin_risk else None),
            "user_risk": (request.user_risk.lower() if request.user_risk else None),
            "auth_flow": (request.auth_flow.lower() if request.auth_flow else None),
            "device_filter": request.device_filter,
        }

        summary, gaps = analyze(
            session=session,
            user_upn=request.user,
            base=base,
            fixed=fixed,
            max_scenarios=request.max_scenarios,
        )

        session.close()
        return {
            "summary": summary,
            "gaps": gaps,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Mount static files (after routes to avoid conflicts)
app.mount("/static", StaticFiles(directory="static"), name="static")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
