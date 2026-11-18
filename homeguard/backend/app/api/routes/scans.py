"""Scan routes reserved for phase 1. This phase does not start Nmap."""

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("")
def list_scans() -> list[dict]:
    return []


@router.post("")
def start_scan() -> None:
    raise HTTPException(
        status_code=501,
        detail={
            "code": "not_in_this_phase",
            "message": "Scan execution starts in phase 1. Phase 0 only checks scope.",
        },
    )
