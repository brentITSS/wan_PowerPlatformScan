from dataclasses import dataclass
from typing import Any

from ppscanner.findings import is_platform_solution, merge_displayed_findings


@dataclass(frozen=True)
class ReportSection:
    title: str
    facts: tuple[str, ...]
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    recommendation: str


def build_sections(snapshot: dict[str, Any]) -> list[ReportSection]:
    snapshot = merge_displayed_findings(snapshot)
    environments = _dicts(snapshot.get("environments"))
    return [
        _environments_section(snapshot, environments),
        _apps_section(environments),
        _sharing_section(environments),
        _flows_section(environments),
        _solutions_section(environments),
        _connectors_section(snapshot, environments),
        _findings_section(snapshot),
    ]


def _environments_section(
    snapshot: dict[str, Any],
    environments: list[dict[str, Any]],
) -> ReportSection:
    rows = []
    unknown_type = False
    for environment in environments:
        environment_type = _environment_type(environment)
        if environment_type == "Unknown":
            unknown_type = True
        rows.append(
            (
                _name(environment),
                environment_type,
                str(environment.get("region") or environment.get("location") or "Unknown"),
                "Yes" if environment.get("dataverse_url") else "No",
                str(environment.get("runtime_state") or environment.get("state") or "Unknown"),
                str(len(_dicts(environment.get("apps")))),
                str(len(_dicts(environment.get("flows")))),
            )
        )
    dlp_status = str(snapshot.get("dlp_collection_status") or "not recorded")
    policy_count = snapshot.get("dlp_policy_count")
    if not isinstance(policy_count, int):
        policy_count = len(_dicts(snapshot.get("dlp_policies")))
    facts = [
        f"{len(environments)} environments were discovered. Data policy collection is {dlp_status}, with {policy_count} policies.",
    ]
    if unknown_type:
        facts.append(
            "At least one environment type was stored as the API resource type, so Sandbox, Production, or Default could not be read from this snapshot."
        )
    facts.extend(_access_facts(environments))
    recommendation_parts = []
    if unknown_type:
        recommendation_parts.append(
            "Rescan so each environment is labelled Sandbox, Production, Default, Developer, or Trial before using type-specific maturity thresholds."
        )
    if dlp_status in {"complete", "partial"} and policy_count == 0:
        recommendation_parts.append(
            "Adopt a tenant data policy and assign it to every environment. No policy was returned, so connector use is not classified as business, non-business, or blocked."
        )
    elif dlp_status not in {"complete", "partial"}:
        recommendation_parts.append(
            "Data policy coverage could not be assessed. Confirm the signed-in admin can list DLP policies before treating this tenant as governed."
        )
    else:
        recommendation_parts.append(
            "Review the environment list against the organisation's environment strategy and confirm each non-production environment has an owner and a retirement plan."
        )
    return ReportSection(
        title="Environments",
        facts=tuple(facts),
        headers=("Environment", "Type", "Region", "Dataverse", "State", "Apps", "Flows"),
        rows=tuple(rows),
        recommendation=" ".join(recommendation_parts),
    )


def _apps_section(environments: list[dict[str, Any]]) -> ReportSection:
    rows = []
    outside = []
    unmanaged = []
    not_assessed = 0
    membership_missing = False
    for environment in environments:
        for app in _dicts(environment.get("apps")):
            membership = str(app.get("solution_membership") or "not collected")
            if membership in {"not_collected", "not collected"}:
                membership_missing = True
            label = _membership_label(membership, app.get("solution_names"))
            display_name = str(app.get("display_name") or app.get("name") or "(unnamed)")
            rows.append(
                (
                    _name(environment),
                    display_name,
                    owner_label(app),
                    shared_with_label(app),
                    str(app.get("managed_status") or "not_assessed"),
                    label,
                )
            )
            if membership in {"not_in_solution", "default_solution_only"}:
                outside.append(display_name)
            if app.get("managed_status") == "unmanaged":
                unmanaged.append(display_name)
            if app.get("managed_status") == "not_assessed":
                not_assessed += 1
    facts = [f"{len(rows)} Power Apps were returned."]
    if outside:
        facts.append(
            f"{len(outside)} are not in a custom solution: {_join_names(outside)}."
        )
    if not_assessed:
        facts.append(
            f"Managed status is unknown for {not_assessed} apps because no matching Dataverse canvas app or model-driven app record was found."
        )
    recommendation = _app_recommendation(outside, unmanaged, not_assessed, membership_missing)
    return ReportSection(
        title="Power Apps",
        facts=tuple(facts),
        headers=("Environment", "App", "Owner", "Shared with", "Managed", "Solution"),
        rows=tuple(rows),
        recommendation=recommendation,
    )


def _sharing_section(environments: list[dict[str, Any]]) -> ReportSection:
    rows: list[tuple[str, str, str, str]] = []
    gaps: list[str] = []
    named: list[str] = []
    for environment in environments:
        for app in _dicts(environment.get("apps")):
            app_name = str(app.get("display_name") or app.get("name") or "(unnamed)")
            status = str(app.get("permissions_collection_status") or "not_collected")
            permissions = app.get("permissions")
            if status != "complete" or not isinstance(permissions, list):
                rows.append((_name(environment), app_name, "Not collected", ""))
                continue
            recipients = [
                principal
                for principal in permissions
                if isinstance(principal, dict)
                and str(principal.get("role_name") or "").casefold() != "owner"
            ]
            reported = app.get("shared_users_count")
            returned_users = sum(
                str(principal.get("principal_type") or "").casefold() == "user"
                for principal in recipients
            )
            if (
                isinstance(reported, int)
                and reported > returned_users
            ):
                gaps.append(
                    f"{app_name} reports {_people_count(reported)} and the permissions list named {returned_users}."
                )
            if not recipients:
                detail = (
                    f"{_people_count(reported)} reported, names not returned"
                    if isinstance(reported, int) and reported > 0
                    else "Not shared"
                )
                rows.append((_name(environment), app_name, detail, ""))
                continue
            for principal in recipients:
                person = _principal_label(principal).split(", ", 1)[0]
                named.append(person)
                rows.append(
                    (
                        _name(environment),
                        app_name,
                        person,
                        str(principal.get("role_name") or ""),
                    )
                )
    if named:
        recommendation = (
            f"Review who can open each app: {_join_names(named)}. "
            "A shared user or group can use the app even when it is not in a solution."
        )
    else:
        recommendation = (
            "No share recipients were named. Where an app still reports a shared-user count, "
            "the permissions list did not return those people."
        )
    if gaps:
        recommendation = f"{' '.join(gaps)} {recommendation}"
    facts = [f"{len(named)} share recipients were named."]
    if gaps:
        facts.extend(gaps)
    return ReportSection(
        title="App sharing",
        facts=tuple(facts),
        headers=("Environment", "App", "Person", "Role"),
        rows=tuple(rows),
        recommendation=recommendation,
    )


def _flows_section(environments: list[dict[str, Any]]) -> ReportSection:
    rows = []
    published_outside = []
    draft_count = 0
    published_count = 0
    membership_missing = False
    for environment in environments:
        for flow in _dicts(environment.get("flows")):
            membership = str(flow.get("solution_membership") or "not collected")
            if membership == "not collected" or "solution_membership" not in flow:
                membership_missing = True
            state = str(flow.get("state") or "Unknown")
            display_name = str(flow.get("display_name") or flow.get("name") or "(unnamed)")
            if state.casefold() == "published":
                published_count += 1
            if state.casefold() == "draft":
                draft_count += 1
            if membership in {"not_in_solution", "default_solution_only"} and state.casefold() == "published":
                published_outside.append(display_name)
            rows.append(
                (
                    _name(environment),
                    display_name,
                    state,
                    owner_label(flow),
                    _membership_label(membership, flow.get("solution_names")),
                    str(flow.get("managed_status") or "not_assessed"),
                )
            )
    facts = [
        f"{len(rows)} cloud flows were returned: {published_count} published and {draft_count} draft."
    ]
    if membership_missing:
        facts.append(
            "Solution membership was not collected for every flow. A published flow can still sit outside a solution."
        )
    if published_outside:
        recommendation = (
            f"Add the published flows that are outside a custom solution ({_join_names(published_outside)}) "
            "to a solution before changing them further. Draft flows can stay while they are being built, "
            "then move into the same solution when they are published."
        )
    elif membership_missing:
        recommendation = (
            "Rescan to record which flows are outside a custom solution. Until then, treat the published "
            "flow count as an inventory, not as evidence that those flows are managed."
        )
    else:
        recommendation = (
            "The collected flows are in custom solutions. Keep later changes inside those solutions and "
            "export them as managed when they are promoted."
        )
    return ReportSection(
        title="Power Automate",
        facts=tuple(facts),
        headers=("Environment", "Flow", "State", "Owner", "Solution", "Managed"),
        rows=tuple(rows),
        recommendation=recommendation,
    )


def _solutions_section(environments: list[dict[str, Any]]) -> ReportSection:
    rows = []
    facts = []
    named: list[str] = []
    for environment in environments:
        solutions = _dicts(environment.get("solutions"))
        if not solutions and environment.get("solutions_collection_status") not in {
            "complete",
            None,
        }:
            facts.append(
                f"{_name(environment)} solution inventory is {environment.get('solutions_collection_status')}."
            )
            continue
        managed = sum(solution.get("managed_status") == "managed" for solution in solutions)
        unmanaged = [
            solution
            for solution in solutions
            if solution.get("managed_status") == "unmanaged"
            and not is_platform_solution(
                str(solution.get("unique_name") or ""),
                _optional_text(solution.get("display_name")),
            )
        ]
        facts.append(
            f"{_name(environment)} has {len(solutions)} solutions: {managed} managed and {len(unmanaged)} custom unmanaged."
        )
        for solution in unmanaged:
            label = str(solution.get("display_name") or solution.get("unique_name") or "(unnamed)")
            named.append(f"{label} ({_name(environment)})")
            rows.append(
                (
                    _name(environment),
                    label,
                    str(solution.get("unique_name") or ""),
                    str(solution.get("version") or "Unknown"),
                    "unmanaged",
                )
            )
    if named:
        recommendation = (
            f"Custom unmanaged solutions are the ALM gap: {_join_names(named)}. "
            "Move those customizations into a managed solution pipeline. The large managed count is mostly Microsoft platform solutions and is not itself a maturity problem."
        )
    elif facts:
        recommendation = (
            "No custom unmanaged solutions were found after excluding Default, Active, Basic, and the Common Data Services Default Solution. Keep new maker work in a custom solution rather than the default solution."
        )
    else:
        recommendation = (
            "Solution managed status was not collected. Rescan before judging application lifecycle management maturity."
        )
    return ReportSection(
        title="Solutions",
        facts=tuple(facts) or ("No solution inventory was stored in this snapshot.",),
        headers=("Environment", "Custom unmanaged solution", "Unique name", "Version", "Managed"),
        rows=tuple(rows),
        recommendation=recommendation,
    )


def _connectors_section(
    snapshot: dict[str, Any],
    environments: list[dict[str, Any]],
) -> ReportSection:
    rows = []
    names: list[str] = []
    for environment in environments:
        status = environment.get("connection_references_collection_status")
        for reference in _dicts(environment.get("connection_references")):
            connector = _connector_label(reference)
            label = str(reference.get("display_name") or connector)
            if label not in names:
                names.append(label)
            rows.append(
                (
                    _name(environment),
                    str(reference.get("display_name") or connector),
                    connector,
                    "Active" if reference.get("state_code") == 0 else str(reference.get("state_code") or "Unknown"),
                )
            )
        if status not in {"complete", None} and not _dicts(environment.get("connection_references")):
            rows.append((_name(environment), "(not collected)", str(status), ""))
    policy_count = snapshot.get("dlp_policy_count")
    if not isinstance(policy_count, int):
        policy_count = len(_dicts(snapshot.get("dlp_policies")))
    dlp_status = str(snapshot.get("dlp_collection_status") or "not recorded")
    facts = [
        f"{len([row for row in rows if row[1] != '(not collected)'])} connection references were stored. Data policy collection is {dlp_status}, with {policy_count} policies.",
    ]
    connections_known = any(
        environment.get("connections_collection_status") == "complete"
        for environment in environments
    )
    if not connections_known:
        facts.append(
            "Connection owners were not collected. A connection reference names a connector, not the person who owns the credential."
        )
    if names and policy_count == 0 and dlp_status in {"complete", "partial"}:
        recommendation = (
            f"Connectors in use include {_join_names(names)}. None of them are classified by a data policy. "
            "Create a policy that decides which of these connectors may be used together, and pay particular attention to SQL Server, SharePoint, and any custom connector."
        )
    elif names:
        recommendation = (
            f"Compare the connectors in use ({_join_names(names)}) with the blocked and business groups in the collected data policies. "
            "A connector reference is a configuration match, not proof that a runtime call was blocked."
        )
    else:
        recommendation = (
            "No connection references were stored. Do not treat that as evidence that the tenant has no connectors until this collection is complete."
        )
    headers = ("Environment", "Connection reference", "Connector", "State")
    if connections_known:
        rows = []
        for environment in environments:
            for connection in _dicts(environment.get("connections")):
                rows.append(
                    (
                        _name(environment),
                        str(connection.get("display_name") or connection.get("name") or "(unnamed)"),
                        _connector_label(connection),
                        owner_label(connection),
                        _connection_shares(connection),
                        str(connection.get("status") or "Unknown"),
                    )
                )
        headers = ("Environment", "Connection", "Connector", "Owner", "Shared with", "State")
        facts[0] = (
            f"{len(rows)} connections were stored. Data policy collection is {dlp_status}, with {policy_count} policies."
        )
    return ReportSection(
        title="Connectors and data policies",
        facts=tuple(facts),
        headers=headers,
        rows=tuple(rows),
        recommendation=recommendation,
    )


def _findings_section(snapshot: dict[str, Any]) -> ReportSection:
    findings = _dicts(snapshot.get("findings"))
    rows = [
        (
            str(finding.get("severity") or ""),
            str(finding.get("status") or ""),
            str(finding.get("environment_name") or ""),
            str(finding.get("resource_name") or ""),
            str(finding.get("summary") or ""),
            str(finding.get("recommendation") or ""),
        )
        for finding in findings
    ]
    high = sum(finding.get("severity") == "high" and finding.get("status") == "confirmed" for finding in findings)
    if not findings:
        recommendation = (
            "No findings were stored. That is not a clean maturity result unless the sections above show complete coverage for environments, apps, flows, solutions, and data policies."
        )
    elif high:
        recommendation = (
            f"Start with the {high} confirmed high findings. Each row has its own recommendation. "
            "Use the section recommendations above to decide the order: data policy first where none exists, then custom unmanaged solutions, then apps and flows that are outside a solution."
        )
    else:
        recommendation = (
            "There is no confirmed high finding in this snapshot. Work through the medium and informational rows, and still read the section recommendations where coverage is partial."
        )
    return ReportSection(
        title="Findings",
        facts=(f"{len(findings)} findings were stored with this snapshot.",),
        headers=("Severity", "Status", "Environment", "Resource", "Summary", "Recommendation"),
        rows=tuple(rows),
        recommendation=recommendation,
    )


def _app_recommendation(
    outside: list[str],
    unmanaged: list[str],
    not_assessed: int,
    membership_missing: bool,
) -> str:
    parts = []
    if outside:
        parts.append(
            f"Move {_join_names(outside)} into a custom solution. An app only in the default solution, or in no solution, cannot be promoted as a managed release."
        )
    if unmanaged:
        parts.append(
            f"{_join_names(unmanaged)} are unmanaged. Package them in a managed solution before they are used as production components."
        )
    if membership_missing:
        parts.append(
            "This snapshot does not yet record whether each app is in a solution. Rescan to produce that count; unknown managed status alone is not that count."
        )
    elif not_assessed and not outside:
        parts.append(
            "Some apps still have unknown managed status. After the next scan, use solution membership rather than a missing Dataverse app row to decide whether they sit outside a solution."
        )
    if not parts:
        parts.append(
            "The collected apps are in custom solutions. Keep later edits in those solutions and review sharing before an app is opened to a wider audience."
        )
    return " ".join(parts)


def _access_facts(environments: list[dict[str, Any]]) -> list[str]:
    facts = []
    for environment in environments:
        managed = environment.get("managed_environment")
        if managed == "enabled":
            managed_text = "Managed Environments is on"
        elif managed == "disabled":
            managed_text = "Managed Environments is off"
        else:
            managed_text = "Managed Environments was not returned"
        status = str(environment.get("role_assignments_collection_status") or "not_collected")
        if status != "complete":
            facts.append(
                f"{_name(environment)}: {managed_text}. Environment admins and makers were not collected."
            )
            continue
        roles = _dicts(environment.get("role_assignments"))
        admins = [
            _role_person(role)
            for role in roles
            if str(role.get("role_name") or "").casefold()
            in {"environmentadmin", "admin", "systemadministrator"}
        ]
        makers = [
            _role_person(role)
            for role in roles
            if str(role.get("role_name") or "").casefold() in {"environmentmaker", "maker"}
        ]
        admin_text = _join_names(admins) if admins else "none recorded"
        maker_text = _join_names(makers) if makers else "none recorded"
        extra = ""
        if not admins and not makers:
            extra = (
                " An empty role list does not include Dataverse System Administrator "
                "or Environment Maker security roles."
            )
        facts.append(
            f"{_name(environment)}: {managed_text}. Admins: {admin_text}. Makers: {maker_text}.{extra}"
        )
    return facts


def _role_person(role: dict[str, Any]) -> str:
    name = role.get("principal_name")
    email = role.get("principal_email")
    if isinstance(name, str) and isinstance(email, str) and name.casefold() != email.casefold():
        return f"{name} ({email})"
    if isinstance(name, str) and name:
        return name
    if isinstance(email, str) and email:
        return email
    return str(role.get("principal_id") or "unknown")


def _connection_shares(connection: dict[str, Any]) -> str:
    shares = connection.get("shares")
    if not isinstance(shares, list) or not shares:
        return "Owner only"
    labels = [
        _principal_label(principal).split(", ", 1)[0]
        for principal in shares
        if isinstance(principal, dict)
        and str(principal.get("role_name") or "").casefold() != "owner"
        and str(principal.get("id") or "").casefold()
        != str(connection.get("owner_id") or "").casefold()
    ]
    if not labels:
        return "Owner only"
    return "; ".join(labels)


def owner_label(record: dict[str, Any]) -> str:
    name = record.get("owner_name") if isinstance(record.get("owner_name"), str) else None
    email = record.get("owner_email") if isinstance(record.get("owner_email"), str) else None
    if name and email and name.casefold() != email.casefold():
        return f"{name} ({email})"
    if name:
        return name
    if email:
        return email
    owner_id = record.get("owner_id")
    if isinstance(owner_id, str) and owner_id:
        return owner_id
    return "Unknown"


def shared_with_label(app: dict[str, Any]) -> str:
    permissions = app.get("permissions")
    status = str(app.get("permissions_collection_status") or "not_collected")
    if status != "complete" or not isinstance(permissions, list):
        return (
            f"{_count(app.get('shared_users_count'))} users, "
            f"{_count(app.get('shared_groups_count'))} groups"
        )
    labels = [
        _principal_label(principal)
        for principal in permissions
        if isinstance(principal, dict)
        and str(principal.get("role_name") or "").casefold() != "owner"
    ]
    reported = app.get("shared_users_count")
    returned_users = sum(
        str(principal.get("principal_type") or "").casefold() == "user"
        for principal in permissions
        if isinstance(principal, dict)
        and str(principal.get("role_name") or "").casefold() != "owner"
    )
    if not labels:
        if isinstance(reported, int) and reported > 0:
            return f"{_people_count(reported)} reported, names not returned"
        return "Not shared"
    if isinstance(reported, int) and reported > returned_users:
        return f"{'; '.join(labels)} ({returned_users} of {reported} reported users)"
    return "; ".join(labels)


def _people_count(count: int) -> str:
    if count == 1:
        return "1 user"
    return f"{count} users"


def _principal_label(principal: dict[str, Any]) -> str:
    name = principal.get("display_name") if isinstance(principal.get("display_name"), str) else None
    email = principal.get("email") if isinstance(principal.get("email"), str) else None
    principal_type = str(principal.get("principal_type") or "")
    if principal_type.casefold() == "tenant":
        who = "Entire tenant"
    elif name and email and name.casefold() != email.casefold():
        who = f"{name} ({email})"
    elif name:
        who = name
    elif email:
        who = email
    else:
        who = str(principal.get("id") or "Unknown")
    role_name = principal.get("role_name")
    if isinstance(role_name, str) and role_name:
        return f"{who}, {role_name}"
    return who


def _environment_type(environment: dict[str, Any]) -> str:
    sku = str(environment.get("environment_sku") or "")
    if not sku or sku.startswith("Microsoft."):
        if environment.get("is_default") is True:
            return "Default"
        return "Unknown"
    if environment.get("is_default") is True and sku.casefold() != "default":
        return f"{sku} (default environment)"
    return sku


def _membership_label(membership: str, names: object) -> str:
    if membership == "not_in_solution":
        return "Not in a solution"
    if membership == "default_solution_only":
        return "Default solution only"
    if membership == "in_custom_solution":
        return str(names or "In a custom solution")
    if membership in {"not_collected", "not collected"}:
        return "Not collected"
    return membership


def _connector_label(reference: dict[str, Any]) -> str:
    connector_id = str(reference.get("connector_id") or "")
    tail = connector_id.rstrip("/").rsplit("/", 1)[-1]
    return tail or str(reference.get("display_name") or "Unknown connector")


def _name(environment: dict[str, Any]) -> str:
    return str(environment.get("display_name") or environment.get("name") or "(unnamed)")


def _count(value: object) -> str:
    return str(value) if isinstance(value, int) and not isinstance(value, bool) else "Unknown"


def _join_names(names: list[str]) -> str:
    unique: list[str] = []
    for name in names:
        if name not in unique:
            unique.append(name)
    if len(unique) > 8:
        return ", ".join(unique[:8]) + f", and {len(unique) - 8} more"
    if len(unique) == 1:
        return unique[0]
    if len(unique) == 2:
        return f"{unique[0]} and {unique[1]}"
    return ", ".join(unique[:-1]) + f", and {unique[-1]}"


def _optional_text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _dicts(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
