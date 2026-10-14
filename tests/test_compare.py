from ppscanner.compare import compare_snapshots


def _snapshot(snapshot_id: str, environments: list[dict]) -> dict:
    return {
        "snapshot_id": snapshot_id,
        "environment_collection_status": "complete",
        "environments": environments,
        "findings": [],
    }


def test_partial_app_inventory_is_not_reported_as_deletion() -> None:
    baseline = _snapshot(
        "baseline",
        [
            {
                "id": "env-1",
                "display_name": "Production",
                "apps_collection_status": "complete",
                "flows_collection_status": "complete",
                "solutions_collection_status": "complete",
                "apps": [{"id": "app-1", "display_name": "Payroll"}],
                "flows": [],
                "solutions": [],
            }
        ],
    )
    current = _snapshot(
        "current",
        [
            {
                "id": "env-1",
                "display_name": "Production",
                "apps_collection_status": "permission_denied",
                "flows_collection_status": "complete",
                "solutions_collection_status": "complete",
                "apps": [],
                "flows": [{"id": "flow-1", "display_name": "Nightly"}],
                "solutions": [],
            }
        ],
    )

    result = compare_snapshots(baseline, current)

    assert result["apps"]["removed"] == []
    assert result["apps"]["added"] == []
    assert result["flows"]["added"][0]["id"] == "flow-1"
    assert any("withheld" in note for note in result["limitations"])


def test_complete_inventories_report_added_and_removed_apps() -> None:
    baseline = _snapshot(
        "baseline",
        [
            {
                "id": "env-1",
                "display_name": "Production",
                "apps_collection_status": "complete",
                "flows_collection_status": "complete",
                "solutions_collection_status": "complete",
                "apps": [{"id": "app-old", "display_name": "Old", "managed_status": "managed"}],
                "flows": [],
                "solutions": [],
            }
        ],
    )
    current = _snapshot(
        "current",
        [
            {
                "id": "env-1",
                "display_name": "Production renamed",
                "apps_collection_status": "complete",
                "flows_collection_status": "complete",
                "solutions_collection_status": "complete",
                "apps": [
                    {"id": "app-old", "display_name": "Old", "managed_status": "unmanaged"}
                ],
                "flows": [],
                "solutions": [],
            }
        ],
    )

    result = compare_snapshots(baseline, current)

    assert result["environments"]["changed"][0]["changes"]["display_name"]["current"] == (
        "Production renamed"
    )
    assert result["apps"]["removed"] == []
    assert result["apps"]["changed"][0]["changes"]["managed_status"] == {
        "baseline": "managed",
        "current": "unmanaged",
    }
