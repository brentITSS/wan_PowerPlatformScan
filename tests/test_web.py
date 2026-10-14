from dataclasses import replace

from fastapi.testclient import TestClient

from ppscanner.findings import evaluate_findings
from ppscanner.models import Environment, PowerApp
from ppscanner.snapshot import create_snapshot, save_snapshot, utc_now
from ppscanner.web import create_app


def test_dashboard_shows_snapshot_findings_and_escapes_names(tmp_path) -> None:
    app_record = replace(
        PowerApp.from_api(
            {"name": "app-1", "properties": {"displayName": "<script>app</script>"}}
        ),
        managed_status="unmanaged",
    )
    environment = replace(
        Environment.from_api(
            {
                "id": "env-1",
                "name": "env-1",
                "properties": {
                    "displayName": "Production",
                    "environmentSku": "Production",
                },
            }
        ),
        apps=[app_record],
        apps_collection_status="complete",
    )
    findings = evaluate_findings([environment], [], "failed", "2026-10-14T00:00:00Z")
    snapshot = create_snapshot(
        "tenant-1",
        utc_now(),
        [environment],
        dlp_collection_status="failed",
        findings=findings,
    )
    save_snapshot(snapshot, tmp_path)
    client = TestClient(create_app(tmp_path))

    index = client.get("/")
    assert index.status_code == 200
    assert snapshot.snapshot_id in index.text

    detail = client.get(f"/snapshots/{snapshot.snapshot_id}")
    assert detail.status_code == 200
    assert "Production" in detail.text

    environment_page = client.get(
        f"/snapshots/{snapshot.snapshot_id}/environments/env-1"
    )
    assert environment_page.status_code == 200
    assert "<script>app</script>" not in environment_page.text
    assert "&lt;script&gt;app&lt;/script&gt;" in environment_page.text

    finding = findings[0]
    finding_page = client.get(f"/snapshots/{snapshot.snapshot_id}/findings/{finding.id}")
    assert finding_page.status_code == 200
    assert finding.rule_id in finding_page.text
    assert "does not change the tenant" in finding_page.text
