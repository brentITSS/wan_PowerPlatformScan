from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta

from ppscanner.models import (
    AppPrincipal,
    CloudFlow,
    Connection,
    DlpPolicy,
    Environment,
    EnvironmentRoleAssignment,
    Finding,
    PowerApp,
)

RULE_VERSION = "2"
STALE_DAYS = 730
CONSUMER_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "yahoo.co.uk",
    "icloud.com",
    "aol.com",
    "msn.com",
    "proton.me",
    "protonmail.com",
}
BROAD_USER_SHARE_THRESHOLD = 25
BROAD_GROUP_SHARE_THRESHOLD = 10
PLATFORM_SOLUTION_UNIQUE_NAMES = {"Default", "Active", "Basic"}
PLATFORM_SOLUTION_DISPLAY_NAMES = {
    "Default Solution",
    "Active Solution",
    "Basic Solution",
    "Common Data Services Default Solution",
}


def is_platform_solution(unique_name: str | None, display_name: str | None) -> bool:
    return unique_name in PLATFORM_SOLUTION_UNIQUE_NAMES or (
        display_name in PLATFORM_SOLUTION_DISPLAY_NAMES
    )

ALM_GUIDANCE = "https://learn.microsoft.com/power-platform/alm/solution-concepts-alm"
DLP_GUIDANCE = "https://learn.microsoft.com/power-platform/admin/wp-data-loss-prevention"
SHARING_GUIDANCE = "https://learn.microsoft.com/power-platform/admin/security/overview"
ENVIRONMENT_GUIDANCE = (
    "https://learn.microsoft.com/power-platform/guidance/adoption/environment-strategy"
)


def evaluate_findings(
    environments: list[Environment],
    dlp_policies: list[DlpPolicy],
    dlp_collection_status: str,
    observed_at: str | None,
) -> list[Finding]:
    findings: list[Finding] = []
    for environment in environments:
        findings.extend(_environment_findings(environment, observed_at))
        findings.extend(_app_findings(environment, observed_at))
        findings.extend(_solution_findings(environment, observed_at))
        findings.extend(_flow_findings(environment, observed_at))
        findings.extend(_connection_findings(environment, observed_at))
    findings.extend(
        _dlp_findings(environments, dlp_policies, dlp_collection_status, observed_at)
    )
    return findings


def _environment_findings(
    environment: Environment,
    observed_at: str | None,
) -> list[Finding]:
    findings: list[Finding] = []
    sku = (environment.environment_sku or "").casefold()
    name = _environment_name(environment)
    if sku in {"developer", "trial"}:
        findings.append(
            _finding(
            rule_id="PP-ENV-DEVELOPER-OR-TRIAL",
            category="environments",
            severity="informational",
            confidence="high",
            status="confirmed",
            environment=environment,
            resource_id=environment.id or environment.name,
            resource_name=name,
            resource_type="environment",
            evidence=(
                f"Environment type is {environment.environment_sku}. "
                "This records the environment for review against your "
                "environment policy. The type is not by itself a defect."
            ),
            source="tenant-admin environment inventory",
            observed_at=observed_at,
            summary=f"{name} is a {environment.environment_sku} environment.",
            recommendation=(
                "Compare this environment with the tenant environment strategy "
                "and confirm that an owner, lifecycle, and data policy are assigned."
            ),
            guidance_url=ENVIRONMENT_GUIDANCE,
            )
        )
    if environment.is_default and (environment.apps or _published_flows(environment)):
        outside_apps = [
            app.display_name or app.name or app.id
            for app in environment.apps
            if app.solution_membership in {"not_in_solution", "default_solution_only"}
        ]
        outside_flows = [
            flow.display_name or flow.name or flow.id
            for flow in _published_flows(environment)
            if flow.solution_membership in {"not_in_solution", "default_solution_only"}
        ]
        findings.append(
            _finding(
                rule_id="PP-ENV-DEFAULT-WORKLOAD",
                category="environments",
                severity="high" if outside_apps or outside_flows else "medium",
                confidence="high",
                status="confirmed",
                environment=environment,
                resource_id=environment.id or environment.name,
                resource_name=name,
                resource_type="environment",
                evidence=(
                    f"{name} is the default environment and contains "
                    f"{len(environment.apps)} apps and "
                    f"{len(_published_flows(environment))} published flows. "
                    + (
                        "Outside a custom solution: "
                        + ", ".join(outside_apps + outside_flows)
                        + "."
                        if outside_apps or outside_flows
                        else "The collected apps and published flows are in custom solutions."
                    )
                ),
                source="tenant-admin environment inventory",
                observed_at=observed_at,
                summary=f"{name} holds the tenant's apps and published flows.",
                recommendation=(
                    "Move business apps and published flows out of the default "
                    "environment into a dedicated environment with its own data policy "
                    "and maker list. Keep the default environment for personal experiments."
                ),
                guidance_url=ENVIRONMENT_GUIDANCE,
            )
        )
    if environment.is_default and environment.managed_environment == "disabled":
        findings.append(
            _finding(
                rule_id="PP-ENV-NOT-MANAGED",
                category="environments",
                severity="high",
                confidence="high",
                status="confirmed",
                environment=environment,
                resource_id=environment.id or environment.name,
                resource_name=name,
                resource_type="environment",
                evidence=(
                    "governanceConfiguration.protectionLevel is Basic, so Managed "
                    "Environments is off for the default environment."
                ),
                source="tenant-admin environment inventory",
                observed_at=observed_at,
                summary=f"Managed Environments is off for {name}.",
                recommendation=(
                    "Turn on Managed Environments for the default environment, "
                    "including sharing limits and the solution checker, or move "
                    "business work to an environment where it is already on."
                ),
                guidance_url=ENVIRONMENT_GUIDANCE,
            )
        )
    if (
        environment.is_default
        and environment.role_assignments_collection_status == "complete"
    ):
        makers = [
            role
            for role in environment.role_assignments
            if (role.role_name or "").casefold() in {"environmentmaker", "maker"}
        ]
        if makers:
            maker_names = ", ".join(_role_label(role) for role in makers)
            findings.append(
                _finding(
                    rule_id="PP-ENV-DEFAULT-MAKERS",
                    category="environments",
                    severity="medium",
                    confidence="high",
                    status="confirmed",
                    environment=environment,
                    resource_id=environment.id or environment.name,
                    resource_name=name,
                    resource_type="environment",
                    evidence=f"Environment Maker assignments: {maker_names}.",
                    source="Power Platform admin environment role assignments",
                    observed_at=observed_at,
                    summary=f"{name} has {len(makers)} environment makers.",
                    recommendation=(
                        "Remove Environment Maker from people who do not need to "
                        "create apps and flows in the default environment."
                    ),
                    guidance_url=ENVIRONMENT_GUIDANCE,
                )
            )
    return findings


def _app_findings(environment: Environment, observed_at: str | None) -> list[Finding]:
    findings: list[Finding] = []
    production = _is_production(environment)
    for app in environment.apps:
        resource_name = app.display_name or app.name or app.id
        if app.solution_membership in {"not_in_solution", "default_solution_only"}:
            outside = app.solution_membership == "not_in_solution"
            findings.append(
                _finding(
                    rule_id="PP-APP-NOT-IN-SOLUTION",
                    category="apps",
                    severity="high" if production else "medium",
                    confidence="high",
                    status="confirmed",
                    environment=environment,
                    resource_id=app.id,
                    resource_name=resource_name,
                    resource_type="app",
                    evidence=(
                        "No Dataverse solution component of type Canvas App (300) "
                        "or App Module (80) references this app."
                        if outside
                        else (
                            "This app's solution components are only in platform "
                            f"solutions ({app.solution_names or 'Default'})."
                        )
                    ),
                    source="Dataverse solutioncomponent",
                    observed_at=observed_at,
                    summary=(
                        f"{resource_name} is not in a custom solution."
                    ),
                    recommendation=(
                        "Add the app to a custom solution and make later changes "
                        "in that solution so it can move between environments."
                    ),
                    guidance_url=ALM_GUIDANCE,
                )
            )
        if production and app.managed_status == "unmanaged":
            findings.append(
                _finding(
                    rule_id="PP-APP-UNMANAGED-PRODUCTION",
                    category="apps",
                    severity="high",
                    confidence="high",
                    status="confirmed",
                    environment=environment,
                    resource_id=app.id,
                    resource_name=resource_name,
                    resource_type="app",
                    evidence=(
                        "Dataverse reported ismanaged false for this app, and "
                        f"the environment type is {environment.environment_sku}."
                    ),
                    source="Dataverse canvasapp.ismanaged or appmodule.ismanaged",
                    observed_at=observed_at,
                    summary=f"{resource_name} is an unmanaged app in a production environment.",
                    recommendation=(
                        "Move the app into a managed solution, or record an approved "
                        "exception if it must remain unmanaged."
                    ),
                    guidance_url=ALM_GUIDANCE,
                )
            )
        user_count = app.shared_users_count
        group_count = app.shared_groups_count
        broad_users = user_count is not None and user_count >= BROAD_USER_SHARE_THRESHOLD
        broad_groups = (
            group_count is not None and group_count >= BROAD_GROUP_SHARE_THRESHOLD
        )
        if broad_users or broad_groups:
            findings.append(
                _finding(
                    rule_id="PP-APP-BROAD-SHARING",
                    category="sharing",
                    severity="medium",
                    confidence="medium",
                    status="potential",
                    environment=environment,
                    resource_id=app.id,
                    resource_name=resource_name,
                    resource_type="app",
                    evidence=(
                        f"The app inventory reported {user_count} shared users and "
                        f"{group_count} shared groups. The baseline treats "
                        f"{BROAD_USER_SHARE_THRESHOLD} or more users, or "
                        f"{BROAD_GROUP_SHARE_THRESHOLD} or more groups, as broad "
                        "sharing. The count does not identify external or "
                        "tenant-wide sharing."
                    ),
                    source="Power Platform API app inventory sharing counts",
                    observed_at=observed_at,
                    summary=f"{resource_name} has a broad reported sharing count.",
                    recommendation=(
                        "Review the app's share list and remove access that is "
                        "wider than the app's audience."
                    ),
                    guidance_url=SHARING_GUIDANCE,
                )
            )
        findings.extend(_share_findings(environment, app, resource_name, observed_at))
        if _is_stale(app.last_modified_time, observed_at):
            findings.append(
                _finding(
                    rule_id="PP-APP-STALE",
                    category="lifecycle",
                    severity="low",
                    confidence="medium",
                    status="confirmed",
                    environment=environment,
                    resource_id=app.id,
                    resource_name=resource_name,
                    resource_type="app",
                    evidence=(
                        f"Last modified {app.last_modified_time}. The baseline treats "
                        f"{STALE_DAYS // 30} months without a change as unmaintained. "
                        "Last modified is not last used."
                    ),
                    source="Power Platform API app inventory",
                    observed_at=observed_at,
                    summary=f"{resource_name} has not been modified in over two years.",
                    recommendation=(
                        "Confirm the app is still required. Retire it, or record an "
                        "owner and a review date if people still use it."
                    ),
                    guidance_url=ENVIRONMENT_GUIDANCE,
                )
            )
        if not app.owner_id:
            findings.append(
                _finding(
                    rule_id="PP-APP-OWNER-MISSING",
                    category="ownership",
                    severity="low",
                    confidence="low",
                    status="potential",
                    environment=environment,
                    resource_id=app.id,
                    resource_name=resource_name,
                    resource_type="app",
                    evidence=(
                        "The app inventory did not include an owner id. A missing "
                        "field is not proof that the app has no owner."
                    ),
                    source="Power Platform API app inventory",
                    observed_at=observed_at,
                    summary=f"{resource_name} has no owner id in the app inventory.",
                    recommendation=(
                        "Confirm the owner in the Power Platform admin center and "
                        "reassign the app if the owner has left."
                    ),
                    guidance_url=SHARING_GUIDANCE,
                )
            )
    return findings


def _solution_findings(
    environment: Environment,
    observed_at: str | None,
) -> list[Finding]:
    findings: list[Finding] = []
    production = _is_production(environment)
    severity = _custom_solution_severity(environment)
    for solution in environment.solutions:
        if solution.managed_status != "unmanaged":
            continue
        if is_platform_solution(solution.unique_name, solution.display_name):
            continue
        resource_name = solution.display_name or solution.unique_name or solution.id
        environment_type = _environment_type_name(environment)
        findings.append(
            _finding(
                rule_id=(
                    "PP-SOL-UNMANAGED-PRODUCTION" if production else "PP-SOL-UNMANAGED"
                ),
                category="solutions",
                severity=severity,
                confidence="high",
                status="confirmed",
                environment=environment,
                resource_id=solution.id or solution.unique_name,
                resource_name=resource_name,
                resource_type="solution",
                evidence=(
                    f"Dataverse solution {solution.unique_name or '(unnamed)'} "
                    "has ismanaged false. Platform solutions, including the "
                    "Common Data Services Default Solution, are excluded. The "
                    f"environment type is {environment_type}."
                ),
                source="Dataverse solution.ismanaged",
                observed_at=observed_at,
                summary=(
                    f"{resource_name} is a custom unmanaged solution in "
                    f"{_environment_name(environment)}."
                ),
                recommendation=(
                    "Move these customizations into a managed solution pipeline "
                    "before they are treated as the environment's source of truth."
                ),
                guidance_url=ALM_GUIDANCE,
            )
        )
    return findings


def _flow_findings(environment: Environment, observed_at: str | None) -> list[Finding]:
    findings: list[Finding] = []
    production = _is_production(environment)
    for flow in environment.flows:
        resource_name = flow.display_name or flow.name or flow.id
        published = (flow.state or "").casefold() == "published"
        if (
            environment.is_default
            and published
            and flow.managed_status == "unmanaged"
        ):
            findings.append(
                _finding(
                    rule_id="PP-FLOW-PUBLISHED-UNMANAGED-DEFAULT",
                    category="flows",
                    severity="medium",
                    confidence="high",
                    status="confirmed",
                    environment=environment,
                    resource_id=flow.id,
                    resource_name=resource_name,
                    resource_type="cloud_flow",
                    evidence=(
                        f"{resource_name} is published and unmanaged in the default "
                        "environment. Managed status comes from the solutions that "
                        "contain the flow."
                    ),
                    source="Dataverse solution.ismanaged for Workflow components",
                    observed_at=observed_at,
                    summary=(
                        f"{resource_name} is a published unmanaged flow in the "
                        "default environment."
                    ),
                    recommendation=(
                        "Export the flow in a managed solution to a dedicated "
                        "environment, or turn it off if it is no longer required."
                    ),
                    guidance_url=ALM_GUIDANCE,
                )
            )
        if published and _is_stale(flow.last_modified_time, observed_at):
            findings.append(
                _finding(
                    rule_id="PP-FLOW-STALE-PUBLISHED",
                    category="lifecycle",
                    severity="low",
                    confidence="medium",
                    status="confirmed",
                    environment=environment,
                    resource_id=flow.id,
                    resource_name=resource_name,
                    resource_type="cloud_flow",
                    evidence=(
                        f"Published flow last modified {flow.last_modified_time}. "
                        "Last modified is not last run."
                    ),
                    source="Power Platform API List Cloud Flows",
                    observed_at=observed_at,
                    summary=f"{resource_name} is published and has not changed in over two years.",
                    recommendation=(
                        "Confirm the flow still runs for a current process. Turn it "
                        "off if the process has ended."
                    ),
                    guidance_url=ALM_GUIDANCE,
                )
            )
        if flow.solution_membership in {"not_in_solution", "default_solution_only"}:
            findings.append(
                _finding(
                    rule_id="PP-FLOW-NOT-IN-SOLUTION",
                    category="flows",
                    severity="high" if production and published else "medium",
                    confidence="high",
                    status="confirmed",
                    environment=environment,
                    resource_id=flow.id,
                    resource_name=resource_name,
                    resource_type="cloud_flow",
                    evidence=(
                        "No Dataverse Workflow solution component (type 29) places "
                        "this flow in a custom solution. "
                        f"State is {flow.state or 'unknown'}."
                    ),
                    source="Dataverse solutioncomponent",
                    observed_at=observed_at,
                    summary=f"{resource_name} is not in a custom solution.",
                    recommendation=(
                        "Add the flow to the same custom solution as the app it "
                        "supports, then export that solution as managed."
                    ),
                    guidance_url=ALM_GUIDANCE,
                )
            )
        if flow.owner_id:
            continue
        resource_name = flow.display_name or flow.name or flow.id
        findings.append(
            _finding(
                rule_id="PP-FLOW-OWNER-MISSING",
                category="ownership",
                severity="low",
                confidence="low",
                status="potential",
                environment=environment,
                resource_id=flow.id,
                resource_name=resource_name,
                resource_type="cloud_flow",
                evidence=(
                    "List Cloud Flows did not include an owner id. A missing "
                    "field is not proof that the flow has no owner. Managed "
                    "status was not assessed because that operation does not "
                    "publish ismanaged."
                ),
                source="Power Platform API List Cloud Flows",
                observed_at=observed_at,
                summary=f"{resource_name} has no owner id in the cloud-flow inventory.",
                recommendation=(
                    "Confirm the flow owner in the environment and reassign it "
                    "if the owner has left."
                ),
                guidance_url=SHARING_GUIDANCE,
            )
        )
    return findings


def _dlp_findings(
    environments: list[Environment],
    policies: list[DlpPolicy],
    dlp_collection_status: str,
    observed_at: str | None,
) -> list[Finding]:
    if dlp_collection_status not in {"complete", "partial"}:
        return []
    unknown = [
        policy
        for policy in policies
        if (policy.environment_type or "")
        not in {"AllEnvironments", "OnlyEnvironments", "ExceptEnvironments"}
    ]
    findings: list[Finding] = []
    for policy in unknown:
        findings.append(
            _finding(
                rule_id="PP-DLP-SCOPE-UNKNOWN",
                category="data_policy",
                severity="informational",
                confidence="high",
                status="not_assessable",
                environment=None,
                resource_id=policy.id,
                resource_name=policy.display_name or policy.id,
                resource_type="dlp_policy",
                evidence=(
                    "The policy environment type "
                    f"{policy.environment_type or '(missing)'} is not one of "
                    "AllEnvironments, OnlyEnvironments, or ExceptEnvironments, "
                    "so environment coverage was not inferred."
                ),
                source="Power Platform for Admins List DLP Policies V2",
                observed_at=observed_at,
                summary=(
                    f"DLP policy {policy.display_name or policy.id} has an "
                    "unrecognized environment scope."
                ),
                recommendation=(
                    "Review the policy in the Power Platform admin center before "
                    "treating any environment as covered or uncovered."
                ),
                guidance_url=DLP_GUIDANCE,
            )
        )
    if unknown:
        return findings

    for environment in environments:
        if not any(
            policy.applies_to(environment.name, environment.id) for policy in policies
        ):
            name = _environment_name(environment)
            findings.append(
                _finding(
                    rule_id="PP-ENV-NO-DLP",
                    category="data_policy",
                    severity="high",
                    confidence="high",
                    status="confirmed",
                    environment=environment,
                    resource_id=environment.id or environment.name,
                    resource_name=name,
                    resource_type="environment",
                    evidence=(
                        f"DLP collection status is {dlp_collection_status}. "
                        f"{len(policies)} policies were returned, and none apply "
                        "to this environment under AllEnvironments, "
                        "OnlyEnvironments, or ExceptEnvironments."
                    ),
                    source="Power Platform for Admins List DLP Policies V2",
                    observed_at=observed_at,
                    summary=f"{name} has no DLP policy assignment in the collected policies.",
                    recommendation=(
                        "Assign a data policy that matches the environment's data "
                        "classification, or record why this environment is exempt."
                    ),
                    guidance_url=DLP_GUIDANCE,
                )
            )
        findings.extend(
            _blocked_connector_findings(
                environment,
                policies,
                observed_at,
            )
        )
    return findings


def _blocked_connector_findings(
    environment: Environment,
    policies: list[DlpPolicy],
    observed_at: str | None,
) -> list[Finding]:
    if environment.connection_references_collection_status != "complete":
        return []
    applicable = [
        policy
        for policy in policies
        if policy.connectors_collected
        and policy.applies_to(environment.name, environment.id) is True
    ]
    blocked = {
        _connector_key(connector.id): connector
        for policy in applicable
        for connector in policy.connectors
        if connector.classification.casefold() == "blocked"
    }
    findings: list[Finding] = []
    for reference in environment.connection_references:
        if not reference.connector_id:
            continue
        connector = blocked.get(_connector_key(reference.connector_id))
        if connector is None:
            continue
        resource_name = reference.display_name or reference.logical_name or reference.id
        findings.append(
            _finding(
                rule_id="PP-CONN-BLOCKED-BY-DLP",
                category="data_policy",
                severity="high",
                confidence="high",
                status="confirmed",
                environment=environment,
                resource_id=reference.id,
                resource_name=resource_name,
                resource_type="connection_reference",
                evidence=(
                    f"Connection reference uses connector {reference.connector_id}, "
                    "and an applicable DLP policy classifies "
                    f"{connector.id} as Blocked. This is a configuration match, "
                    "not an observation of a blocked runtime call."
                ),
                source=(
                    "Dataverse connectionreference.connectorid and DLP "
                    "connectorGroups classification Blocked"
                ),
                observed_at=observed_at,
                summary=(
                    f"{resource_name} references a connector classified as Blocked "
                    "by an applicable DLP policy."
                ),
                recommendation=(
                    "Remove the connection reference or change the data policy "
                    "only after confirming the connector is approved for this data."
                ),
                guidance_url=DLP_GUIDANCE,
            )
        )
    return findings


def _share_findings(
    environment: Environment,
    app: PowerApp,
    resource_name: str,
    observed_at: str | None,
) -> list[Finding]:
    if app.permissions_collection_status != "complete":
        return []
    findings: list[Finding] = []
    recipients = [
        principal
        for principal in app.permissions
        if (principal.role_name or "").casefold() != "owner"
    ]
    named_users = sum(
        (principal.principal_type or "").casefold() == "user" for principal in recipients
    )
    if app.shared_users_count is not None and app.shared_users_count > named_users:
        findings.append(
            _finding(
                rule_id="PP-APP-SHARE-LIST-INCOMPLETE",
                category="sharing",
                severity="medium",
                confidence="high",
                status="confirmed",
                environment=environment,
                resource_id=app.id,
                resource_name=resource_name,
                resource_type="app",
                evidence=(
                    f"The app inventory reports {app.shared_users_count} shared users. "
                    f"The permissions list named {named_users}."
                ),
                source="Power Apps admin app role assignments",
                observed_at=observed_at,
                summary=(
                    f"{resource_name} has a shared-user count larger than the named list."
                ),
                recommendation=(
                    "Do not treat the named share list as complete. Open the app's "
                    "share dialog and account for every person the count includes."
                ),
                guidance_url=SHARING_GUIDANCE,
            )
        )
    for principal in recipients:
        kind = _external_share_kind(principal, app.owner_email)
        if kind is None:
            continue
        who = principal.display_name or principal.email or principal.id
        findings.append(
            _finding(
                rule_id="PP-APP-EXTERNAL-SHARE",
                category="sharing",
                severity="high" if kind in {"consumer", "guest"} else "medium",
                confidence="high",
                status="confirmed",
                environment=environment,
                resource_id=app.id,
                resource_name=resource_name,
                resource_type="app",
                evidence=(
                    f"{who} ({principal.email or principal.principal_type or 'unknown'}) "
                    f"has {principal.role_name or 'an unstated role'}. "
                    f"The address is a {kind.replace('-', ' ')} share."
                ),
                source="Power Apps admin app role assignments",
                observed_at=observed_at,
                summary=f"{resource_name} is shared outside the organisation with {who}.",
                recommendation=(
                    "Remove the share unless this person is an approved guest, and "
                    "turn on a sharing limit so consumer accounts cannot be added again."
                ),
                guidance_url=SHARING_GUIDANCE,
            )
        )
    return findings


def _connection_findings(
    environment: Environment,
    observed_at: str | None,
) -> list[Finding]:
    if environment.connections_collection_status != "complete":
        return []
    findings: list[Finding] = []
    for connection in environment.connections:
        recipients = [
            principal
            for principal in connection.shares
            if (principal.role_name or "").casefold() not in {"owner", ""}
            and (principal.id or "").casefold() != (connection.owner_id or "").casefold()
        ]
        external = [
            principal
            for principal in recipients
            if _external_share_kind(principal, connection.owner_email) is not None
        ]
        if not recipients:
            continue
        resource_name = connection.display_name or connection.name or connection.id
        named = ", ".join(
            principal.display_name or principal.email or principal.id
            for principal in recipients
        )
        findings.append(
            _finding(
                rule_id="PP-CONN-SHARED",
                category="connectors",
                severity="high" if external else "medium",
                confidence="high",
                status="confirmed",
                environment=environment,
                resource_id=connection.id,
                resource_name=resource_name,
                resource_type="connection",
                evidence=(
                    f"Connection owner is {connection.owner_name or connection.owner_id or 'unknown'}. "
                    f"Shared with {named}. A connection share is access to the credential, "
                    "not only to an app."
                ),
                source="Power Apps admin connection role assignments",
                observed_at=observed_at,
                summary=f"{resource_name} is shared beyond its owner.",
                recommendation=(
                    "Remove shares that are wider than the flow or app that uses this "
                    "connection. Prefer a connection owned by a service account over one "
                    "shared from a person."
                ),
                guidance_url=DLP_GUIDANCE,
            )
        )
    return findings


def _external_share_kind(
    principal: AppPrincipal,
    owner_email: str | None,
) -> str | None:
    email = principal.email or ""
    if "#ext#" in email.casefold() or (principal.principal_type or "").casefold() == "guest":
        return "guest"
    domain = _email_domain(email)
    if not domain:
        return None
    if domain in CONSUMER_EMAIL_DOMAINS:
        return "consumer"
    owner_domain = _email_domain(owner_email or "")
    if owner_domain and domain != owner_domain:
        return "other-organisation"
    return None


def _email_domain(email: str) -> str:
    if "@" not in email:
        return ""
    return email.rsplit("@", 1)[-1].casefold().strip()


def _published_flows(environment: Environment) -> list[CloudFlow]:
    return [
        flow
        for flow in environment.flows
        if (flow.state or "").casefold() == "published"
    ]


def _role_label(role: EnvironmentRoleAssignment) -> str:
    return role.principal_name or role.principal_email or role.principal_id or "unknown"


def _is_stale(modified: str | None, observed_at: str | None) -> bool:
    modified_at = _parse_time(modified)
    observed = _parse_time(observed_at)
    if modified_at is None or observed is None:
        return False
    return observed - modified_at >= timedelta(days=STALE_DAYS)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def merge_displayed_findings(snapshot: dict[str, object]) -> dict[str, object]:
    stored = snapshot.get("findings")
    stored_findings = stored if isinstance(stored, list) else []
    try:
        evaluated = evaluate_findings(
            _environments_from_snapshot(snapshot),
            _policies_from_snapshot(snapshot),
            str(snapshot.get("dlp_collection_status") or "not_collected"),
            _optional_snapshot_text(snapshot.get("completed_at")),
        )
    except (TypeError, ValueError):
        return snapshot
    seen = {
        (item.get("rule_id"), item.get("resource_id"))
        for item in stored_findings
        if isinstance(item, dict)
    }
    extra = [
        asdict(finding)
        for finding in evaluated
        if (finding.rule_id, finding.resource_id) not in seen
    ]
    if not extra:
        return snapshot
    return {**snapshot, "findings": [*stored_findings, *extra]}


def _environments_from_snapshot(snapshot: dict[str, object]) -> list[Environment]:
    environments = snapshot.get("environments")
    if not isinstance(environments, list):
        return []
    rebuilt: list[Environment] = []
    for record in environments:
        if isinstance(record, dict):
            rebuilt.append(_environment_from_record(record))
    return rebuilt


def _environment_from_record(record: dict[str, object]) -> Environment:
    environment = Environment.from_api(
        {
            "id": record.get("id") or "",
            "name": record.get("name") or record.get("id") or "",
            "properties": {
                "displayName": record.get("display_name"),
                "environmentSku": record.get("environment_sku"),
                "isDefault": record.get("is_default") is True,
                "governanceConfiguration": _governance_from_record(record),
            },
        }
    )
    apps = [
        _app_from_record(item)
        for item in record.get("apps") or []
        if isinstance(item, dict)
    ]
    flows = [
        _flow_from_record(item)
        for item in record.get("flows") or []
        if isinstance(item, dict)
    ]
    roles = [
        EnvironmentRoleAssignment(
            id=str(item.get("id") or ""),
            role_name=_optional_snapshot_text(item.get("role_name")),
            principal_id=_optional_snapshot_text(item.get("principal_id")),
            principal_name=_optional_snapshot_text(item.get("principal_name")),
            principal_email=_optional_snapshot_text(item.get("principal_email")),
            principal_type=_optional_snapshot_text(item.get("principal_type")),
        )
        for item in record.get("role_assignments") or []
        if isinstance(item, dict)
    ]
    connections = [
        _connection_from_record(item)
        for item in record.get("connections") or []
        if isinstance(item, dict)
    ]
    return replace(
        environment,
        is_default=record.get("is_default") if isinstance(record.get("is_default"), bool) else None,
        managed_environment=_optional_snapshot_text(record.get("managed_environment")),
        apps=apps,
        flows=flows,
        role_assignments=roles,
        role_assignments_collection_status=str(
            record.get("role_assignments_collection_status") or "not_collected"
        ),
        connections=connections,
        connections_collection_status=str(
            record.get("connections_collection_status") or "not_collected"
        ),
    )


def _governance_from_record(record: dict[str, object]) -> dict[str, str] | None:
    managed = record.get("managed_environment")
    if managed == "enabled":
        return {"protectionLevel": "Standard"}
    if managed == "disabled":
        return {"protectionLevel": "Basic"}
    return None


def _app_from_record(record: dict[str, object]) -> PowerApp:
    app = PowerApp.from_api(
        {
            "name": record.get("name") or record.get("id") or "app",
            "id": record.get("id") or "",
            "properties": {
                "displayName": record.get("display_name"),
                "lastModifiedTime": record.get("last_modified_time"),
                "sharedUsersCount": record.get("shared_users_count"),
                "sharedGroupsCount": record.get("shared_groups_count"),
                "owner": {"id": record.get("owner_id"), "type": record.get("owner_type")},
            },
        }
    )
    permissions = tuple(
        AppPrincipal(
            id=str(item.get("id") or ""),
            display_name=_optional_snapshot_text(item.get("display_name")),
            email=_optional_snapshot_text(item.get("email")),
            principal_type=_optional_snapshot_text(item.get("principal_type")),
            role_name=_optional_snapshot_text(item.get("role_name")),
        )
        for item in record.get("permissions") or []
        if isinstance(item, dict)
    )
    return replace(
        app,
        owner_email=_optional_snapshot_text(record.get("owner_email")),
        managed_status=str(record.get("managed_status") or "not_assessed"),
        solution_membership=str(record.get("solution_membership") or "not_collected"),
        solution_names=_optional_snapshot_text(record.get("solution_names")),
        permissions=permissions,
        permissions_collection_status=str(
            record.get("permissions_collection_status") or "not_collected"
        ),
    )


def _flow_from_record(record: dict[str, object]) -> CloudFlow:
    flow = CloudFlow.from_api(
        {
            "workflowId": record.get("id"),
            "uniqueName": record.get("name"),
            "name": record.get("display_name"),
            "stateCode": record.get("state"),
            "modifiedOn": record.get("last_modified_time"),
            "ownerId": record.get("owner_id"),
        }
    )
    return replace(
        flow,
        managed_status=str(record.get("managed_status") or "not_assessed"),
        solution_membership=str(record.get("solution_membership") or "not_collected"),
        owner_name=_optional_snapshot_text(record.get("owner_name")),
        owner_email=_optional_snapshot_text(record.get("owner_email")),
    )


def _connection_from_record(record: dict[str, object]) -> Connection:
    shares = tuple(
        AppPrincipal(
            id=str(item.get("id") or ""),
            display_name=_optional_snapshot_text(item.get("display_name")),
            email=_optional_snapshot_text(item.get("email")),
            principal_type=_optional_snapshot_text(item.get("principal_type")),
            role_name=_optional_snapshot_text(item.get("role_name")),
        )
        for item in record.get("shares") or []
        if isinstance(item, dict)
    )
    return Connection(
        id=str(record.get("id") or ""),
        name=str(record.get("name") or ""),
        display_name=_optional_snapshot_text(record.get("display_name")),
        connector_id=_optional_snapshot_text(record.get("connector_id")),
        status=_optional_snapshot_text(record.get("status")),
        owner_id=_optional_snapshot_text(record.get("owner_id")),
        owner_name=_optional_snapshot_text(record.get("owner_name")),
        owner_email=_optional_snapshot_text(record.get("owner_email")),
        environment_id=_optional_snapshot_text(record.get("environment_id")),
        shares=shares,
    )


def _policies_from_snapshot(snapshot: dict[str, object]) -> list[DlpPolicy]:
    policies = snapshot.get("dlp_policies")
    if not isinstance(policies, list):
        return []
    rebuilt: list[DlpPolicy] = []
    for record in policies:
        if isinstance(record, dict):
            rebuilt.append(
                DlpPolicy(
                    id=str(record.get("id") or ""),
                    display_name=_optional_snapshot_text(record.get("display_name")),
                    environment_type=_optional_snapshot_text(record.get("environment_type")),
                    environment_ids=[],
                    default_classification=_optional_snapshot_text(
                        record.get("default_classification")
                    ),
                    connectors=[],
                    connectors_collected=record.get("connectors_collected") is True,
                    created_time=None,
                    last_modified_time=None,
                )
            )
    return rebuilt


def _optional_snapshot_text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _finding(
    *,
    rule_id: str,
    category: str,
    severity: str,
    confidence: str,
    status: str,
    environment: Environment | None,
    resource_id: str | None,
    resource_name: str | None,
    resource_type: str | None,
    evidence: str,
    source: str,
    observed_at: str | None,
    summary: str,
    recommendation: str,
    guidance_url: str | None,
) -> Finding:
    environment_id = None if environment is None else environment.id or environment.name
    environment_name = None if environment is None else _environment_name(environment)
    identity = ":".join(
        part for part in (rule_id, environment_id or "tenant", resource_id or "") if part
    )
    return Finding(
        id=identity,
        rule_id=rule_id,
        rule_version=RULE_VERSION,
        category=category,
        severity=severity,
        confidence=confidence,
        status=status,
        environment_id=environment_id,
        environment_name=environment_name,
        resource_id=resource_id,
        resource_name=resource_name,
        resource_type=resource_type,
        evidence=evidence,
        source=source,
        observed_at=observed_at,
        summary=summary,
        recommendation=recommendation,
        guidance_url=guidance_url,
    )


def _environment_name(environment: Environment) -> str:
    return environment.display_name or environment.name or environment.id or "(unnamed)"


def _is_production(environment: Environment) -> bool:
    return _environment_type_name(environment).casefold() == "production"


def _environment_type_name(environment: Environment) -> str:
    sku = environment.environment_sku or ""
    if not sku or sku.startswith("Microsoft."):
        if environment.is_default is True:
            return "Default"
        return "Unknown"
    return sku


def _custom_solution_severity(environment: Environment) -> str:
    sku = _environment_type_name(environment).casefold()
    if sku == "production":
        return "high"
    if sku in {"developer", "trial"}:
        return "informational"
    return "medium"


def _connector_key(value: str) -> str:
    return value.rstrip("/").rsplit("/", 1)[-1].casefold()
