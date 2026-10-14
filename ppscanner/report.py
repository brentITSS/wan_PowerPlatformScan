import csv
import json
from html import escape
from pathlib import Path
from typing import Any

from ppscanner.narrative import build_sections, owner_label, shared_with_label


def write_json_report(snapshot: dict[str, Any], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return output


def write_csv_report(snapshot: dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(
        output_dir / "environments.csv",
        (
            "id",
            "display_name",
            "environment_sku",
            "region",
            "state",
            "apps_collection_status",
            "flows_collection_status",
            "solutions_collection_status",
            "connection_references_collection_status",
        ),
        snapshot.get("environments") or [],
    )
    _write_child_csv(
        output_dir / "apps.csv",
        snapshot,
        "apps",
        (
            "environment_id",
            "environment_name",
            "id",
            "display_name",
            "app_type",
            "managed_status",
            "solution_membership",
            "solution_names",
            "owner_id",
            "owner",
            "shared_with",
            "shared_users_count",
            "shared_groups_count",
        ),
    )
    _write_child_csv(
        output_dir / "flows.csv",
        snapshot,
        "flows",
        (
            "environment_id",
            "environment_name",
            "id",
            "display_name",
            "state",
            "status",
            "owner_id",
            "owner",
            "managed_status",
            "solution_membership",
            "solution_names",
        ),
    )
    _write_child_csv(
        output_dir / "solutions.csv",
        snapshot,
        "solutions",
        (
            "environment_id",
            "environment_name",
            "id",
            "unique_name",
            "display_name",
            "version",
            "managed_status",
        ),
    )
    _write_child_csv(
        output_dir / "connection_references.csv",
        snapshot,
        "connection_references",
        (
            "environment_id",
            "environment_name",
            "id",
            "display_name",
            "logical_name",
            "connector_id",
            "state_code",
        ),
    )
    _write_csv(
        output_dir / "dlp_policies.csv",
        (
            "id",
            "display_name",
            "environment_type",
            "default_classification",
            "connectors_collected",
        ),
        snapshot.get("dlp_policies") or [],
    )
    _write_csv(
        output_dir / "findings.csv",
        (
            "id",
            "rule_id",
            "severity",
            "confidence",
            "status",
            "environment_name",
            "resource_type",
            "resource_name",
            "summary",
            "evidence",
            "recommendation",
            "guidance_url",
        ),
        snapshot.get("findings") or [],
    )
    return output_dir


def render_html_report(snapshot: dict[str, Any]) -> str:
    coverage = _coverage_notes(snapshot)
    coverage_items = "\n".join(f"<li>{escape(note)}</li>" for note in coverage)
    sections = "\n".join(_section_html(section) for section in build_sections(snapshot))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Power Platform maturity report {escape(str(snapshot.get("snapshot_id") or ""))}</title>
  <style>
    body {{ font-family: Segoe UI, sans-serif; margin: 2rem; color: #1b1b1b; background: #fff; line-height: 1.45; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #666; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }}
    th {{ background: #f3f3f3; }}
    .recommendation {{ background: #f7f1e8; border-left: 4px solid #6b4f2a; padding: 0.8rem 1rem; margin: 0 0 2rem; }}
    h1, h2 {{ margin-bottom: 0.4rem; }}
  </style>
</head>
<body>
  <h1>Power Platform maturity and risk report</h1>
  <p>Snapshot {escape(str(snapshot.get("snapshot_id") or ""))}
     for tenant {escape(str(snapshot.get("tenant_id") or ""))}.</p>
  <p>Started {escape(str(snapshot.get("started_at") or ""))}
     and completed {escape(str(snapshot.get("completed_at") or ""))}.
     Scanner {escape(str(snapshot.get("scanner_version") or ""))}.
     This report describes what the scan could see. It is not a certification that the tenant is safe.</p>
  <h2>Coverage</h2>
  <ul>
    {coverage_items}
  </ul>
  {sections}
</body>
</html>
"""


def _section_html(section) -> str:
    facts = "\n".join(f"<p>{escape(fact)}</p>" for fact in section.facts)
    if section.rows:
        header = "".join(f"<th>{escape(column)}</th>" for column in section.headers)
        body = "\n".join(
            "<tr>" + "".join(f"<td>{escape(cell)}</td>" for cell in row) + "</tr>"
            for row in section.rows
        )
        table = f"<table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table>"
    else:
        table = ""
    return (
        f"<h2>{escape(section.title)}</h2>"
        f"{facts}"
        f"{table}"
        f"<p class=\"recommendation\"><strong>Recommendation.</strong> "
        f"{escape(section.recommendation)}</p>"
    )


def write_html_report(snapshot: dict[str, Any], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_html_report(snapshot), encoding="utf-8")
    return output


def _coverage_notes(snapshot: dict[str, Any]) -> list[str]:
    environment_count = snapshot.get("environment_count")
    notes = [
        (
            f"Environment discovery is {snapshot.get('environment_collection_status')} "
            f"with scope {snapshot.get('environment_scope')} "
            f"({environment_count} environments)."
        ),
        (
            "App inventory coverage: "
            f"{_coverage_text(snapshot.get('app_environment_coverage'))}."
        ),
        (
            "Cloud flow inventory coverage: "
            f"{_coverage_text(snapshot.get('flow_environment_coverage'))}. "
            f"{snapshot.get('flow_managed_status_source_api') or ''}"
        ),
        (
            "Solution inventory coverage: "
            f"{_coverage_text(snapshot.get('solution_environment_coverage'))}."
        ),
        (
            f"DLP collection is {snapshot.get('dlp_collection_status') or 'not present'}."
        ),
    ]
    error = snapshot.get("dlp_collection_error")
    if isinstance(error, str) and error:
        notes.append(error)
    notes.append(
        "A missing resource in a partial collection is not evidence that it was deleted."
    )
    return notes


def _coverage_text(value: object) -> str:
    if not isinstance(value, dict):
        return "not recorded"
    return f"{value.get('complete', 0)} of {value.get('total', 0)} environments complete"


def _write_child_csv(
    path: Path,
    snapshot: dict[str, Any],
    collection_name: str,
    fields: tuple[str, ...],
) -> None:
    rows: list[dict[str, Any]] = []
    for environment in _dicts(snapshot.get("environments")):
        for record in _dicts(environment.get(collection_name)):
            row = {
                "environment_id": environment.get("id"),
                "environment_name": environment.get("display_name"),
                **record,
            }
            if collection_name in {"apps", "flows"}:
                row["owner"] = owner_label(record)
            if collection_name == "apps":
                row["shared_with"] = shared_with_label(record)
            rows.append(row)
    _write_csv(path, fields, rows)


def _write_csv(path: Path, fields: tuple[str, ...], rows: object) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in _dicts(rows):
            writer.writerow({field: row.get(field) for field in fields})


def _dicts(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
