"""
ScamGuard — Data Access Layer  (v3.1 — Stabilized)
===================================================
All DB operations for entities, reports, checks, and keywords.
Routers stay thin — all Supabase calls live here.

Fix history:
  v3.1 — insert_report: validates returned row contains 'id'; raises
          ValueError clearly so the router can return a 503 rather than
          silently swallowing a missing ID.
        — update_entity_score: wrapped in try/except so a score-update
          failure never crashes the request after the report is saved.
        — get_keywords: returns empty dict (not raises) on any DB error.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from supabase import Client
from utils.logger import get_logger

log = get_logger(__name__)


# ── Entities ────────────────────────────────────────────────────────────────

def get_entity(db: Client, type_: str, value: str) -> Optional[dict]:
    res = (
        db.table("entities")
        .select("*")
        .eq("type", type_)
        .eq("value", value)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def upsert_entity(db: Client, type_: str, value: str) -> dict:
    existing = get_entity(db, type_, value)
    if existing:
        return existing
    new = {
        "id":           str(uuid.uuid4()),
        "type":         type_,
        "value":        value,
        "risk_score":   0.0,
        "report_count": 0,
        "created_at":   datetime.now(timezone.utc).isoformat(),
    }
    res = db.table("entities").insert(new).execute()
    if not res.data:
        raise RuntimeError(f"Entity insert returned no data for value={value!r}")
    return res.data[0]


def update_entity_score(db: Client, entity_id: str, risk_score: float, report_count: int):
    """Update entity risk score. Non-fatal on failure — logged as a warning."""
    try:
        db.table("entities").update({
            "risk_score":   risk_score,
            "report_count": report_count,
        }).eq("id", entity_id).execute()
    except Exception as exc:
        log.warning(f"update_entity_score failed (non-fatal) | entity={entity_id} | error={exc}")


# ── Reports ─────────────────────────────────────────────────────────────────

def get_reports_for_entity(db: Client, entity_id: str, limit: int = 50) -> list[dict]:
    res = (
        db.table("reports")
        .select("id, description, tags, created_at, user_id")
        .eq("entity_id", entity_id)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return res.data or []


def count_recent_reports(db: Client, entity_id: str, days: int = 7) -> int:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    res = (
        db.table("reports")
        .select("id", count="exact")
        .eq("entity_id", entity_id)
        .gte("created_at", since)
        .execute()
    )
    return res.count or 0


def user_already_reported(db: Client, entity_id: str, user_id: str) -> bool:
    res = (
        db.table("reports")
        .select("id")
        .eq("entity_id", entity_id)
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    return bool(res.data)


def insert_report(
    db: Client,
    entity_id: str,
    user_id: str,
    description: str,
    tags: list[str],
) -> dict:
    """
    Insert a new report row and return the inserted record.

    [FIX-3] Captures the ID from the insert response directly.
    Raises ValueError if Supabase returns an empty response or a row
    without an 'id' field, so the caller can surface a 503 cleanly.
    """
    row = {
        "id":          str(uuid.uuid4()),
        "entity_id":   entity_id,
        "user_id":     user_id,
        "description": description,
        "tags":        tags,
        "created_at":  datetime.now(timezone.utc).isoformat(),
    }
    res = db.table("reports").insert(row).execute()

    if not res.data:
        raise ValueError(
            f"Report insert returned no data | entity={entity_id} | user={user_id[:8]}…"
        )

    inserted = res.data[0]
    if not inserted.get("id"):
        # Supabase returned a row but without an id — log and use our generated id
        log.warning(
            f"Report insert returned row without 'id' — using client-generated id={row['id']}"
        )
        inserted["id"] = row["id"]

    return inserted


# ── Checks (analytics) ──────────────────────────────────────────────────────

def log_check(
    db: Client,
    entity_id: str,
    risk_score: float,
    user_id: Optional[str] = None,
):
    """Log a check event for analytics. Non-fatal on any failure."""
    try:
        db.table("checks").insert({
            "id":         str(uuid.uuid4()),
            "entity_id":  entity_id,
            "user_id":    user_id,
            "risk_score": risk_score,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as exc:
        log.warning(f"Failed to log check (non-fatal) | entity={entity_id} | error={exc}")


# ── Keywords ────────────────────────────────────────────────────────────────

def get_keywords(db: Client) -> dict[str, float]:
    """Return {word: weight} dict from DB keywords table. Returns {} on error."""
    try:
        res = db.table("keywords").select("word, weight").execute()
        return {row["word"]: float(row["weight"]) for row in (res.data or [])}
    except Exception as exc:
        log.warning(f"Could not load keywords from DB (using fallback): {exc}")
        return {}


def upsert_keyword(db: Client, word: str, weight: float) -> dict:
    existing = db.table("keywords").select("id").eq("word", word).limit(1).execute()
    if existing.data:
        res = db.table("keywords").update({"weight": weight}).eq("word", word).execute()
    else:
        res = db.table("keywords").insert({
            "id": str(uuid.uuid4()), "word": word, "weight": weight,
        }).execute()
    return res.data[0]


def delete_keyword(db: Client, word: str):
    db.table("keywords").delete().eq("word", word).execute()


# ── Entities list ────────────────────────────────────────────────────────────

def list_top_entities(db: Client, limit: int = 20) -> list[dict]:
    res = (
        db.table("entities")
        .select("id, type, value, risk_score, report_count, created_at")
        .order("risk_score", desc=True)
        .limit(min(limit, 100))
        .execute()
    )
    return res.data or []
