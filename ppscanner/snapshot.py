import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from ppscanner import __version__
from ppscanner.models import DlpPolicy, Environment, Finding, Snapshot

SOURCE_API = (
    "Power Platform admin List Environments "
    "(api.bap.microsoft.com, API version 2020-10-01)"
)
SOURCE_API_STATUS = "preview"
APP_SOURCE_API = (
    "Power Platform API PowerApps Get AdminApps "
    "(api.powerplatform.com, API version 2024-10-01)"
)
APP_SOURCE_API_STATUS = "preview"
FLOW_SOURCE_API = (
    "Power Platform API Power Automate List Cloud Flows "
    "(api.powerplatform.com, API version 2024-10-01)"
)
FLOW_SOURCE_API_STATUS = "preview"
SOLUTION_SOURCE_API = "Dataverse Web API v9.2 solution.ismanaged"
CONNECTION_REFERENCE_SOURCE_API = (
    "Dataverse Web API v9.2 connectionreference "
    "(connector identifier and display name only)"
)
DLP_SOURCE_API = (
    "Power Platform for Admins List DLP Policies V2 "
    "(api.bap.microsoft.com/providers/PowerPlatform.Governance/v2/policies, "
    "API version 2016-11-01)"
)
DLP_SOURCE_API_STATUS = "admin-connector"


def utc_now() -> datetime:
    return datetime.now(UTC)


def create_snapshot(
    tenant_id: str,
    started_at: datetime,
    environments: list[Environment],
    dlp_policies: list[DlpPolicy] | None = None,
    dlp_collection_status: str = "not_collected",
    dlp_collection_error: str | None = None,
    findings: list[Finding] | None = None,
) -> Snapshot:
    completed_at = utc_now()
    snapshot_id = completed_at.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    return Snapshot(
        snapshot_id=snapshot_id,
        tenant_id=tenant_id,
        scanner_version=__version__,
        started_at=started_at.isoformat(),
        completed_at=completed_at.isoformat(),
        source_api=SOURCE_API,
        source_api_status=SOURCE_API_STATUS,
        environments=environments,
        environment_scope="tenant_admin",
        environment_collection_status="complete",
        app_source_api=APP_SOURCE_API,
        app_source_api_status=APP_SOURCE_API_STATUS,
        flow_source_api=FLOW_SOURCE_API,
        flow_source_api_status=FLOW_SOURCE_API_STATUS,
        solution_source_api=SOLUTION_SOURCE_API,
        connection_reference_source_api=CONNECTION_REFERENCE_SOURCE_API,
        dlp_source_api=DLP_SOURCE_API,
        dlp_source_api_status=DLP_SOURCE_API_STATUS,
        dlp_policies=dlp_policies or [],
        dlp_collection_status=dlp_collection_status,
        dlp_collection_error=dlp_collection_error,
        findings=findings or [],
    )


def read_snapshot(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{path.name} could not be read as a snapshot.") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("snapshot_id"), str):
        raise TypeError(f"{path.name} is not a scanner snapshot.")
    return payload


def list_snapshots(directory: Path) -> list[dict[str, object]]:
    if not directory.is_dir():
        return []
    snapshots: list[dict[str, object]] = []
    for path in directory.glob("*.json"):
        try:
            snapshots.append(read_snapshot(path))
        except ValueError:
            continue
    snapshots.sort(key=lambda item: str(item.get("completed_at") or ""), reverse=True)
    return snapshots


def latest_snapshot_path(directory: Path) -> Path | None:
    snapshots = list_snapshots(directory)
    if not snapshots:
        return None
    snapshot_id = snapshots[0]["snapshot_id"]
    return directory / f"{snapshot_id}.json"


def save_snapshot(snapshot: Snapshot, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{snapshot.snapshot_id}.json"
    temporary = target.with_suffix(".json.tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(snapshot.to_dict(), stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    temporary.replace(target)
    return target
