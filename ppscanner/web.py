from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.templating import Jinja2Templates

from ppscanner.narrative import owner_label, shared_with_label
from ppscanner.snapshot import list_snapshots

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
TEMPLATES.env.filters["quote_path"] = lambda value: quote(str(value), safe="")
TEMPLATES.env.filters["owner_label"] = owner_label
TEMPLATES.env.filters["shared_with_label"] = shared_with_label


def create_app(snapshots_dir: Path) -> FastAPI:
    app = FastAPI(title="Power Platform Tenant Scanner")

    @app.get("/")
    def index(request: Request) -> object:
        snapshots = [
            {
                "snapshot_id": snapshot.get("snapshot_id"),
                "completed_at": snapshot.get("completed_at"),
                "environment_count": snapshot.get("environment_count"),
                "finding_count": snapshot.get("finding_count", 0),
            }
            for snapshot in list_snapshots(snapshots_dir)
        ]
        return TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {"request": request, "title": "Snapshots", "snapshots": snapshots},
        )

    @app.get("/snapshots/{snapshot_id}")
    def snapshot_detail(request: Request, snapshot_id: str) -> object:
        snapshot = _require(snapshots_dir, snapshot_id)
        return TEMPLATES.TemplateResponse(
            request,
            "snapshot.html",
            {
                "request": request,
                "title": snapshot_id,
                "snapshot": snapshot,
                "findings": _findings(snapshot),
            },
        )

    @app.get("/snapshots/{snapshot_id}/environments/{environment_id:path}")
    def environment_detail(
        request: Request,
        snapshot_id: str,
        environment_id: str,
    ) -> object:
        snapshot = _require(snapshots_dir, snapshot_id)
        environment = _environment(snapshot, environment_id)
        if environment is None:
            raise HTTPException(status_code=404, detail="Environment was not found.")
        findings = [
            finding
            for finding in _findings(snapshot)
            if finding.get("environment_id") == environment.get("id")
        ]
        return TEMPLATES.TemplateResponse(
            request,
            "environment.html",
            {
                "request": request,
                "title": environment.get("display_name") or environment_id,
                "snapshot": snapshot,
                "environment": environment,
                "findings": findings,
            },
        )

    @app.get("/snapshots/{snapshot_id}/findings")
    def findings_page(request: Request, snapshot_id: str) -> object:
        snapshot = _require(snapshots_dir, snapshot_id)
        return TEMPLATES.TemplateResponse(
            request,
            "findings.html",
            {
                "request": request,
                "title": "Findings",
                "snapshot": snapshot,
                "findings": _findings(snapshot),
            },
        )

    @app.get("/snapshots/{snapshot_id}/findings/{finding_id:path}")
    def finding_detail(request: Request, snapshot_id: str, finding_id: str) -> object:
        snapshot = _require(snapshots_dir, snapshot_id)
        finding = next(
            (item for item in _findings(snapshot) if item.get("id") == finding_id),
            None,
        )
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding was not found.")
        return TEMPLATES.TemplateResponse(
            request,
            "finding.html",
            {
                "request": request,
                "title": finding.get("summary") or "Finding",
                "snapshot": snapshot,
                "finding": finding,
            },
        )

    return app


def _require(snapshots_dir: Path, snapshot_id: str) -> dict[str, Any]:
    for snapshot in list_snapshots(snapshots_dir):
        if snapshot.get("snapshot_id") == snapshot_id:
            return snapshot
    raise HTTPException(status_code=404, detail="Snapshot was not found.")


def _environment(snapshot: dict[str, Any], environment_id: str) -> dict[str, Any] | None:
    environments = snapshot.get("environments")
    if not isinstance(environments, list):
        return None
    for environment in environments:
        if isinstance(environment, dict) and environment.get("id") == environment_id:
            return environment
    return None


def _findings(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    findings = snapshot.get("findings")
    if not isinstance(findings, list):
        return []
    return [finding for finding in findings if isinstance(finding, dict)]
