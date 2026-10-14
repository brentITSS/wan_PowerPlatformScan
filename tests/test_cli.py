from typer.testing import CliRunner

import ppscanner.auth
from ppscanner.cli import app


def test_scan_reports_missing_configuration_without_authentication(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PP_TENANT_ID", raising=False)
    monkeypatch.delenv("PP_CLIENT_ID", raising=False)
    monkeypatch.setattr(ppscanner.auth, "load_dotenv", lambda: None)

    result = CliRunner().invoke(app, ["scan"])

    assert result.exit_code == 1
    assert "Missing PP_TENANT_ID, PP_CLIENT_ID" in result.output
    assert "Traceback" not in result.output


def test_environments_reports_a_missing_snapshot(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["environments"])

    assert result.exit_code == 1
    assert "No snapshots found" in result.output


def test_report_rejects_an_unknown_format(tmp_path) -> None:
    snapshot = tmp_path / "snap.json"
    snapshot.write_text(
        '{"snapshot_id": "snap-1", "environments": [], "findings": []}',
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        ["report", "--snapshot", str(snapshot), "--format", "pdf"],
    )

    assert result.exit_code == 1
    assert "Format must be json, csv, or html." in result.output


def test_environments_lists_collected_cloud_flows(tmp_path) -> None:
    snapshot = tmp_path / "snap.json"
    snapshot.write_text(
        """
        {
          "snapshot_id": "snap-1",
          "environments": [
            {
              "id": "env-1",
              "display_name": "ITSS_DEV",
              "environment_sku": "Sandbox",
              "state": "Succeeded",
              "apps": [],
              "flows": [
                {
                  "display_name": "Process Doc",
                  "state": "Published",
                  "owner_id": "owner-1",
                  "managed_status": "not_assessed"
                }
              ],
              "solutions": []
            }
          ],
          "findings": []
        }
        """,
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["environments", "--snapshot", str(snapshot)])

    assert result.exit_code == 0
    assert "Power Automate" in result.output
    assert "Process Doc" in result.output
    assert "Published" in result.output
