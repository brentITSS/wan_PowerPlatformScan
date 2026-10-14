from typing import Any


def compare_snapshots(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    limitations: list[str] = []
    if baseline.get("environment_collection_status") != "complete":
        limitations.append(
            "The baseline environment inventory is not complete, so environment removals are not reported."
        )
    if current.get("environment_collection_status") != "complete":
        limitations.append(
            "The current environment inventory is not complete, so a missing environment is not reported as removed."
        )
    environment_removals = (
        baseline.get("environment_collection_status") == "complete"
        and current.get("environment_collection_status") == "complete"
    )
    environments = _compare_records(
        _by_id(_records(baseline, "environments"), "id"),
        _by_id(_records(current, "environments"), "id"),
        ("display_name", "environment_sku", "state", "region"),
        report_removed=environment_removals,
    )

    apps = _compare_children(
        baseline,
        current,
        "apps",
        "apps_collection_status",
        ("display_name", "managed_status", "owner_id", "shared_users_count", "shared_groups_count"),
        limitations,
        "app",
    )
    flows = _compare_children(
        baseline,
        current,
        "flows",
        "flows_collection_status",
        ("display_name", "state", "status", "owner_id"),
        limitations,
        "cloud flow",
    )
    solutions = _compare_children(
        baseline,
        current,
        "solutions",
        "solutions_collection_status",
        ("display_name", "unique_name", "managed_status", "version"),
        limitations,
        "solution",
    )
    findings_available = "findings" in baseline and "findings" in current
    if not findings_available:
        limitations.append(
            "One snapshot has no evaluated findings, so finding changes are not reported."
        )
    findings = _compare_records(
        _by_id(baseline.get("findings") if findings_available else [], "id"),
        _by_id(current.get("findings") if findings_available else [], "id"),
        ("severity", "status", "summary"),
        report_removed=findings_available,
    )
    return {
        "baseline_snapshot_id": baseline.get("snapshot_id"),
        "current_snapshot_id": current.get("snapshot_id"),
        "limitations": limitations,
        "environments": environments,
        "apps": apps,
        "flows": flows,
        "solutions": solutions,
        "findings": findings,
    }


def _compare_children(
    baseline: dict[str, Any],
    current: dict[str, Any],
    collection_name: str,
    status_name: str,
    fields: tuple[str, ...],
    limitations: list[str],
    label: str,
) -> dict[str, list[dict[str, Any]]]:
    current_by_environment = {
        str(environment.get("id") or ""): environment
        for environment in _records(current, "environments")
    }
    baseline_records: dict[str, dict[str, Any]] = {}
    current_records: dict[str, dict[str, Any]] = {}
    comparable: set[str] = set()
    for environment in _records(baseline, "environments"):
        environment_id = str(environment.get("id") or "")
        other = current_by_environment.get(environment_id)
        baseline_status = environment.get(status_name)
        current_status = None if other is None else other.get(status_name)
        if baseline_status != "complete" or current_status != "complete":
            limitations.append(
                f"{label.capitalize()} changes are withheld for "
                f"{environment.get('display_name') or environment_id or 'an environment'} "
                f"because inventory status is baseline {baseline_status or 'not collected'} "
                f"and current {current_status or 'not collected'}."
            )
            continue
        comparable.add(environment_id)
        for record in _records(environment, collection_name):
            baseline_records[f"{environment_id}:{record.get('id') or ''}"] = {
                **record,
                "environment_id": environment_id,
                "environment_name": environment.get("display_name"),
            }
        assert other is not None
        for record in _records(other, collection_name):
            current_records[f"{environment_id}:{record.get('id') or ''}"] = {
                **record,
                "environment_id": environment_id,
                "environment_name": other.get("display_name"),
            }
    for environment in _records(current, "environments"):
        environment_id = str(environment.get("id") or "")
        if environment_id in comparable:
            continue
        if environment_id in {
            str(item.get("id") or "") for item in _records(baseline, "environments")
        }:
            continue
        if environment.get(status_name) == "complete":
            limitations.append(
                f"{label.capitalize()} additions are withheld for "
                f"{environment.get('display_name') or environment_id} "
                "because the baseline snapshot has no matching environment inventory."
            )
    return _compare_records(
        baseline_records,
        current_records,
        fields,
        report_removed=True,
        removable_prefixes=comparable,
    )


def _compare_records(
    baseline: dict[str, dict[str, Any]],
    current: dict[str, dict[str, Any]],
    fields: tuple[str, ...],
    report_removed: bool,
    removable_prefixes: set[str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    added = [
        _public_record(record)
        for key, record in current.items()
        if key not in baseline
    ]
    removed: list[dict[str, Any]] = []
    if report_removed:
        for key, record in baseline.items():
            if key in current:
                continue
            prefix = key.split(":", 1)[0]
            if removable_prefixes is not None and prefix not in removable_prefixes:
                continue
            removed.append(_public_record(record))
    changed = []
    for key, record in current.items():
        previous = baseline.get(key)
        if previous is None:
            continue
        differences = {
            field: {"baseline": previous.get(field), "current": record.get(field)}
            for field in fields
            if previous.get(field) != record.get(field)
        }
        if differences:
            changed.append({**_public_record(record), "changes": differences})
    return {"added": added, "removed": removed, "changed": changed}


def _records(payload: dict[str, Any], name: str) -> list[dict[str, Any]]:
    value = payload.get(name)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _by_id(records: list[dict[str, Any]] | object, field: str) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list):
        return {}
    return {
        str(record.get(field) or ""): record
        for record in records
        if isinstance(record, dict) and record.get(field)
    }


def _public_record(record: dict[str, Any]) -> dict[str, Any]:
    hidden = {"changes"}
    return {key: value for key, value in record.items() if key not in hidden}
