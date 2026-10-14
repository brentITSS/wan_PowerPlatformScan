import csv

from ppscanner.report import render_html_report, write_csv_report


def test_html_report_escapes_resource_names_and_states_coverage() -> None:
    html = render_html_report(
        {
            "snapshot_id": "snap-1",
            "tenant_id": "tenant-1",
            "started_at": "2026-10-14T00:00:00+00:00",
            "completed_at": "2026-10-14T00:01:00+00:00",
            "scanner_version": "0.2.0",
            "environment_collection_status": "complete",
            "environment_scope": "tenant_admin",
            "environment_count": 1,
            "app_environment_coverage": {"complete": 1, "total": 1},
            "flow_environment_coverage": {"complete": 0, "total": 1},
            "flow_managed_status_source_api": "Not assessed.",
            "solution_environment_coverage": {"complete": 1, "total": 1},
            "dlp_collection_status": "complete",
            "findings": [
                {
                    "severity": "high",
                    "status": "confirmed",
                    "environment_name": "<script>alert(1)</script>",
                    "resource_name": "Payroll",
                    "summary": "Unmanaged app",
                    "recommendation": "Move it.",
                    "guidance_url": "https://learn.microsoft.com/power-platform/alm/solution-concepts-alm",
                }
            ],
        }
    )

    assert "<script>alert" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "tenant_admin" in html
    assert "Not assessed." in html
    assert "Recommendation." in html


def test_csv_report_omits_flow_definitions(tmp_path) -> None:
    write_csv_report(
        {
            "environments": [
                {
                    "id": "env-1",
                    "display_name": "Production",
                    "environment_sku": "Production",
                    "region": "ukwest",
                    "state": "Enabled",
                    "apps_collection_status": "complete",
                    "flows_collection_status": "complete",
                    "solutions_collection_status": "complete",
                    "connection_references_collection_status": "complete",
                    "apps": [],
                    "flows": [
                        {
                            "id": "flow-1",
                            "display_name": "Nightly",
                            "state": "Published",
                            "status": "1",
                            "owner_id": "owner-1",
                            "managed_status": "not_assessed",
                            "definition": '{"secret":"do-not-export"}',
                        }
                    ],
                    "solutions": [],
                    "connection_references": [],
                }
            ],
            "dlp_policies": [],
            "findings": [],
        },
        tmp_path,
    )

    with (tmp_path / "flows.csv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))

    assert rows[0]["display_name"] == "Nightly"
    assert "definition" not in rows[0]
    assert "do-not-export" not in (tmp_path / "flows.csv").read_text(encoding="utf-8")
