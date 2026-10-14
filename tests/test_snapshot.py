import json
from dataclasses import replace
from datetime import UTC, datetime

from ppscanner.models import Environment, PowerApp
from ppscanner.snapshot import create_snapshot, save_snapshot


def test_environment_type_prefers_sku_over_resource_type() -> None:
    environment = Environment.from_api(
        {
            "name": "env-1",
            "type": "Microsoft.BusinessAppPlatform/scopes/environments",
            "properties": {"environmentSku": "Sandbox", "isDefault": False},
        }
    )

    assert environment.environment_sku == "Sandbox"


def test_environment_normalization_omits_personal_metadata() -> None:
    environment = Environment.from_api(
        {
            "id": "/environments/id-1",
            "name": "id-1",
            "location": "unitedstates",
            "properties": {
                "displayName": "Production",
                "environmentSku": "Production",
                "provisioningState": "Succeeded",
                "states": {
                    "management": {"id": "Ready"},
                    "runtime": {"id": "Enabled"},
                },
                "createdBy": {"displayName": "A user", "id": "personal-id"},
            },
        }
    )

    assert environment.display_name == "Production"
    assert environment.state == "Succeeded"
    assert environment.environment_sku == "Production"
    assert environment.management_state == "Ready"
    assert environment.runtime_state == "Enabled"
    assert environment.dataverse_url is None
    assert "createdBy" not in environment.__dict__


def test_environment_normalization_accepts_dataverse_instance_url() -> None:
    environment = Environment.from_api(
        {
            "name": "id-1",
            "properties": {
                "linkedEnvironmentMetadata": {
                    "instanceUrl": "https://org.crm.dynamics.com/"
                }
            },
        }
    )

    assert environment.dataverse_url == "https://org.crm.dynamics.com"


def test_snapshot_is_saved_with_provenance(tmp_path) -> None:
    environment = Environment.from_api(
        {"name": "environment-1", "properties": {"displayName": "Test"}}
    )
    environment = replace(
        environment,
        apps=[
            PowerApp.from_api(
                {
                    "name": "app-1",
                    "properties": {
                        "displayName": "Canvas app",
                        "sharedUsersCount": 4,
                    },
                },
                environment_id="environment-1",
            )
        ],
        apps_collection_status="complete",
    )
    snapshot = create_snapshot(
        "tenant-1",
        datetime(2026, 10, 12, tzinfo=UTC),
        [environment],
    )

    path = save_snapshot(snapshot, tmp_path)
    saved = json.loads(path.read_text(encoding="utf-8"))

    assert path.exists()
    assert saved["tenant_id"] == "tenant-1"
    assert saved["environment_count"] == 1
    assert saved["source_api_status"] == "preview"
    assert saved["environment_scope"] == "tenant_admin"
    assert saved["environment_collection_status"] == "complete"
    assert saved["managed_status_source_api"] == (
        "Dataverse Web API v9.2 canvasapp.ismanaged and appmodule.ismanaged"
    )
    assert saved["app_count"] == 1
    assert saved["app_environment_coverage"] == {"complete": 1, "total": 1}
    assert saved["environments"][0]["display_name"] == "Test"
    assert saved["environments"][0]["apps"][0]["display_name"] == "Canvas app"
    assert saved["environments"][0]["apps"][0]["managed_status"] == "not_assessed"
