from collections.abc import Callable
from dataclasses import replace
from uuid import UUID

from ppscanner.auth import AuthenticationError
from ppscanner.client import PowerPlatformAdminClient, PowerPlatformApiError
from ppscanner.findings import is_platform_solution
from ppscanner.models import (
    AppPrincipal,
    CloudFlow,
    Connection,
    ConnectionReference,
    DlpPolicy,
    Environment,
    EnvironmentRoleAssignment,
    PowerApp,
    Solution,
)


def collect_apps(
    client: PowerPlatformAdminClient,
    environments: list[Environment],
) -> list[Environment]:
    collected: list[Environment] = []
    for environment in environments:
        try:
            raw_apps = client.list_apps(environment.name or environment.id)
        except PowerPlatformApiError as error:
            status = (
                "permission_denied" if error.status_code in (401, 403) else "failed"
            )
            collected.append(
                replace(
                    environment,
                    apps_collection_status=status,
                    apps_collection_error=str(error),
                )
            )
        else:
            collected.append(
                replace(
                    environment,
                    apps=[
                        PowerApp.from_api(
                            app,
                            environment_id=environment.name or environment.id,
                        )
                        for app in raw_apps
                    ],
                    apps_collection_status="complete",
                    apps_collection_error=None,
                )
            )
    return collected


def collect_app_permissions(
    client: PowerPlatformAdminClient,
    environments: list[Environment],
) -> list[Environment]:
    collected: list[Environment] = []
    for environment in environments:
        if environment.apps_collection_status != "complete":
            collected.append(
                replace(
                    environment,
                    app_permissions_collection_status="partial",
                    app_permissions_collection_error=(
                        "App inventory is incomplete, so share recipients were not read."
                    ),
                )
            )
            continue
        if not environment.apps:
            collected.append(
                replace(
                    environment,
                    app_permissions_collection_status="complete",
                    app_permissions_collection_error=None,
                )
            )
            continue
        apps: list[PowerApp] = []
        errors: list[str] = []
        for app in environment.apps:
            app_name = app.name or app.id
            try:
                raw_permissions = client.list_app_permissions(
                    environment.name or environment.id,
                    app_name,
                )
            except PowerPlatformApiError as error:
                apps.append(
                    replace(
                        app,
                        permissions_collection_status=_status_for_error(error),
                        permissions_collection_error=str(error),
                    )
                )
                errors.append(f"{app.display_name or app_name}: {error}")
                continue
            principals = tuple(
                principal
                for item in raw_permissions
                if (principal := _app_principal(item)) is not None
            )
            owner = _matching_owner(app.owner_id, principals)
            apps.append(
                replace(
                    app,
                    permissions=principals,
                    owner_name=owner.display_name if owner else None,
                    owner_email=owner.email if owner else None,
                    permissions_collection_status="complete",
                    permissions_collection_error=None,
                )
            )
        if not errors:
            status, error_text = "complete", None
        elif len(errors) == len(environment.apps):
            status, error_text = "failed", "; ".join(errors)
        else:
            status, error_text = "partial", "; ".join(errors)
        collected.append(
            replace(
                environment,
                apps=apps,
                app_permissions_collection_status=status,
                app_permissions_collection_error=error_text,
            )
        )
    return collected


def collect_environment_access(
    client: PowerPlatformAdminClient,
    environments: list[Environment],
) -> list[Environment]:
    collected: list[Environment] = []
    for environment in environments:
        try:
            raw_roles = client.list_environment_role_assignments(
                environment.name or environment.id
            )
        except PowerPlatformApiError as error:
            collected.append(
                replace(
                    environment,
                    role_assignments_collection_status=_status_for_error(error),
                    role_assignments_collection_error=str(error),
                )
            )
            continue
        collected.append(
            replace(
                environment,
                role_assignments=[
                    EnvironmentRoleAssignment.from_api(item) for item in raw_roles
                ],
                role_assignments_collection_status="complete",
                role_assignments_collection_error=None,
            )
        )
    return collected


def collect_connections(
    client: PowerPlatformAdminClient,
    environments: list[Environment],
) -> list[Environment]:
    collected: list[Environment] = []
    for environment in environments:
        environment_name = environment.name or environment.id
        try:
            raw_connections = client.list_connections(environment_name)
        except PowerPlatformApiError as error:
            collected.append(
                replace(
                    environment,
                    connections_collection_status=_status_for_error(error),
                    connections_collection_error=str(error),
                )
            )
            continue
        connections: list[Connection] = []
        errors: list[str] = []
        for item in raw_connections:
            connection = Connection.from_api(item, environment_id=environment_name)
            connector_name = (connection.connector_id or "").rstrip("/").rsplit("/", 1)[-1]
            if not connector_name or not connection.name:
                connections.append(connection)
                continue
            try:
                raw_permissions = client.list_connection_permissions(
                    environment_name,
                    connector_name,
                    connection.name,
                )
            except PowerPlatformApiError as error:
                errors.append(f"{connection.display_name or connection.name}: {error}")
                connections.append(connection)
                continue
            shares = tuple(
                principal
                for permission in raw_permissions
                if (principal := _app_principal(permission)) is not None
            )
            connections.append(replace(connection, shares=shares))
        if not errors:
            status, error_text = "complete", None
        else:
            status, error_text = "partial", "; ".join(errors)
        collected.append(
            replace(
                environment,
                connections=connections,
                connections_collection_status=status,
                connections_collection_error=error_text,
            )
        )
    return collected


def collect_app_managed_statuses(
    client: PowerPlatformAdminClient,
    environments: list[Environment],
    acquire_dataverse_token: Callable[[str], str],
) -> list[Environment]:
    collected: list[Environment] = []
    for environment in environments:
        apps = environment.apps
        if not apps:
            status = (
                "complete"
                if environment.apps_collection_status == "complete"
                else "partial"
            )
            collected.append(
                replace(
                    environment,
                    app_managed_status_collection_status=status,
                    app_managed_status_collection_error=(
                        None
                        if status == "complete"
                        else "App inventory is incomplete; managed status coverage is incomplete."
                    ),
                )
            )
            continue
        if not environment.dataverse_url:
            collected.append(
                _with_managed_status_error(
                    environment,
                    "unsupported",
                    "No Dataverse instance URL is available for this environment.",
                )
            )
            continue
        try:
            token = acquire_dataverse_token(environment.dataverse_url)
            managed_apps = client.list_app_managed_statuses(
                environment.dataverse_url,
                token,
                [power_app.id for power_app in apps],
            )
        except AuthenticationError as error:
            collected.append(
                _with_managed_status_error(
                    environment,
                    "permission_denied",
                    str(error),
                )
            )
            continue
        except PowerPlatformApiError as error:
            status = (
                "permission_denied" if error.status_code in (401, 403) else "failed"
            )
            collected.append(
                _with_managed_status_error(environment, status, str(error))
            )
            continue

        updated_apps = [
            replace(
                power_app,
                managed_status=(
                    "managed"
                    if managed_apps.get(_guid_from_app_id(power_app.id)) is True
                    else (
                        "unmanaged"
                        if managed_apps.get(_guid_from_app_id(power_app.id)) is False
                        else "not_assessed"
                    )
                ),
            )
            for power_app in apps
        ]
        assessed_count = sum(
            app.managed_status != "not_assessed" for app in updated_apps
        )
        complete = assessed_count == len(updated_apps)
        app_coverage_complete = environment.apps_collection_status == "complete"
        status = "complete" if complete and app_coverage_complete else "partial"
        collected.append(
            replace(
                environment,
                apps=updated_apps,
                app_managed_status_collection_status=status,
                app_managed_status_collection_error=(
                    None
                    if status == "complete"
                    else (
                        f"Managed status was resolved for {assessed_count} of "
                        f"{len(updated_apps)} returned apps; app inventory "
                        f"status is {environment.apps_collection_status}."
                    )
                ),
            )
        )
    return collected


def _with_managed_status_error(
    environment: Environment,
    status: str,
    error: str,
) -> Environment:
    return replace(
        environment,
        app_managed_status_collection_status=status,
        app_managed_status_collection_error=error,
    )


def collect_flows(
    client: PowerPlatformAdminClient,
    environments: list[Environment],
    access_token: str | None,
    auth_error: str | None = None,
) -> list[Environment]:
    if not access_token:
        message = auth_error or (
            "Power Automate delegated PowerAutomate.Flows.Read access "
            "was not acquired."
        )
        return [
            replace(
                environment,
                flows_collection_status="permission_denied",
                flows_collection_error=message,
            )
            for environment in environments
        ]

    collected: list[Environment] = []
    for environment in environments:
        environment_id = environment.name or environment.id
        try:
            raw_flows = client.list_cloud_flows(environment_id, access_token)
        except PowerPlatformApiError as error:
            status = _status_for_error(error)
            collected.append(
                replace(
                    environment,
                    flows_collection_status=status,
                    flows_collection_error=str(error),
                )
            )
        else:
            collected.append(
                replace(
                    environment,
                    flows=[
                        CloudFlow.from_api(flow, environment_id=environment_id)
                        for flow in raw_flows
                    ],
                    flows_collection_status="complete",
                    flows_collection_error=None,
                )
            )
    return collected


def collect_dataverse_inventory(
    client: PowerPlatformAdminClient,
    environments: list[Environment],
    acquire_dataverse_token: Callable[[str], str],
) -> list[Environment]:
    collected: list[Environment] = []
    for environment in environments:
        if not environment.dataverse_url:
            message = "No Dataverse instance URL is available for this environment."
            collected.append(
                replace(
                    environment,
                    solutions_collection_status="unsupported",
                    solutions_collection_error=message,
                    connection_references_collection_status="unsupported",
                    connection_references_collection_error=message,
                    solution_membership_collection_status="unsupported",
                    solution_membership_collection_error=message,
                    flow_owner_collection_status="unsupported",
                    flow_owner_collection_error=message,
                )
            )
            continue
        try:
            token = acquire_dataverse_token(environment.dataverse_url)
        except AuthenticationError as error:
            collected.append(
                replace(
                    environment,
                    solutions_collection_status="permission_denied",
                    solutions_collection_error=str(error),
                    connection_references_collection_status="permission_denied",
                    connection_references_collection_error=str(error),
                    solution_membership_collection_status="permission_denied",
                    solution_membership_collection_error=str(error),
                    flow_owner_collection_status="permission_denied",
                    flow_owner_collection_error=str(error),
                )
            )
            continue

        environment_id = environment.name or environment.id
        try:
            raw_solutions = client.list_solutions(environment.dataverse_url, token)
        except PowerPlatformApiError as error:
            status = _status_for_error(error)
            updated = replace(
                environment,
                solutions_collection_status=status,
                solutions_collection_error=str(error),
            )
        else:
            updated = replace(
                environment,
                solutions=[
                    Solution.from_api(solution, environment_id=environment_id)
                    for solution in raw_solutions
                ],
                solutions_collection_status="complete",
                solutions_collection_error=None,
            )

        try:
            raw_references = client.list_connection_references(
                environment.dataverse_url,
                token,
            )
        except PowerPlatformApiError as error:
            status = _status_for_error(error)
            updated = replace(
                updated,
                connection_references_collection_status=status,
                connection_references_collection_error=str(error),
            )
        else:
            updated = replace(
                updated,
                connection_references=[
                    ConnectionReference.from_api(
                        reference,
                        environment_id=environment_id,
                    )
                    for reference in raw_references
                ],
                connection_references_collection_status="complete",
                connection_references_collection_error=None,
            )
        updated = _collect_solution_membership(client, updated, token)
        updated = _collect_directory_names(client, updated, token)
        collected.append(updated)
    return collected


def _collect_solution_membership(
    client: PowerPlatformAdminClient,
    environment: Environment,
    token: str,
) -> Environment:
    if environment.solutions_collection_status != "complete":
        return replace(
            environment,
            solution_membership_collection_status="partial",
            solution_membership_collection_error=(
                "Solution inventory is incomplete, so app and flow solution "
                "membership was not assessed."
            ),
        )
    if not environment.dataverse_url:
        return environment
    object_ids = [
        _guid_from_app_id(app.id) for app in environment.apps if _guid_from_app_id(app.id)
    ]
    object_ids.extend(
        _guid_from_app_id(flow.id) for flow in environment.flows if _guid_from_app_id(flow.id)
    )
    if not object_ids:
        return replace(
            environment,
            solution_membership_collection_status="complete",
            solution_membership_collection_error=None,
        )
    try:
        components = client.list_solution_components(
            environment.dataverse_url,
            token,
            object_ids,
        )
    except PowerPlatformApiError as error:
        return replace(
            environment,
            solution_membership_collection_status=_status_for_error(error),
            solution_membership_collection_error=str(error),
        )
    solutions_by_id = {solution.id.casefold(): solution for solution in environment.solutions}
    by_object: dict[str, list[dict[str, object]]] = {}
    for component in components:
        object_id = str(component.get("objectid") or "").casefold()
        if object_id:
            by_object.setdefault(object_id, []).append(component)
    apps = [
        _with_solution_membership(app, by_object.get(_guid_from_app_id(app.id).casefold(), []), solutions_by_id)
        for app in environment.apps
    ]
    flows = [
        _with_solution_membership(
            flow,
            by_object.get(_guid_from_app_id(flow.id).casefold(), []),
            solutions_by_id,
            update_managed_status=True,
        )
        for flow in environment.flows
    ]
    return replace(
        environment,
        apps=apps,
        flows=flows,
        solution_membership_collection_status="complete",
        solution_membership_collection_error=None,
    )


def _with_solution_membership(resource, components, solutions_by_id, update_managed_status=False):
    matched = []
    for component in components:
        solution_id = str(component.get("_solutionid_value") or "").casefold()
        solution = solutions_by_id.get(solution_id)
        if solution is not None:
            matched.append(solution)
    if not components:
        membership = "not_in_solution"
        names = None
    elif not matched:
        membership = "in_custom_solution"
        names = None
    elif all(
        is_platform_solution(solution.unique_name, solution.display_name)
        for solution in matched
    ):
        membership = "default_solution_only"
        names = _solution_name_list(matched)
    else:
        membership = "in_custom_solution"
        names = _solution_name_list(matched)
    managed_status = resource.managed_status
    if update_managed_status and matched:
        statuses = {solution.managed_status for solution in matched}
        if "unmanaged" in statuses:
            managed_status = "unmanaged"
        elif statuses == {"managed"}:
            managed_status = "managed"
    return replace(
        resource,
        solution_membership=membership,
        solution_names=names,
        managed_status=managed_status,
    )


def _solution_name_list(solutions) -> str:
    names = []
    for solution in solutions:
        label = solution.display_name or solution.unique_name
        if label and label not in names:
            names.append(label)
    return ", ".join(names)


def collect_dlp_policies(
    client: PowerPlatformAdminClient,
) -> tuple[list[DlpPolicy], str, str | None]:
    try:
        listed = client.list_dlp_policies()
    except PowerPlatformApiError as error:
        status = (
            "permission_denied" if error.status_code in (401, 403) else "failed"
        )
        return [], status, str(error)

    policies: list[DlpPolicy] = []
    missing_connectors = False
    for item in listed:
        definition = item.get("policyDefinition")
        source = definition if isinstance(definition, dict) else item
        policy_id = source.get("name") if isinstance(source, dict) else None
        detail = item
        if isinstance(policy_id, str) and policy_id:
            try:
                detail = client.get_dlp_policy(policy_id)
            except PowerPlatformApiError:
                missing_connectors = True
                detail = item
        policy = DlpPolicy.from_api(detail)
        if not policy.connectors_collected:
            missing_connectors = True
        policies.append(policy)

    if missing_connectors:
        return (
            policies,
            "partial",
            "Connector classifications were not returned for every DLP policy.",
        )
    return policies, "complete", None


def _collect_directory_names(
    client: PowerPlatformAdminClient,
    environment: Environment,
    token: str,
) -> Environment:
    object_ids = []
    for flow in environment.flows:
        if flow.owner_id and not flow.owner_name:
            object_ids.append(flow.owner_id)
    for app in environment.apps:
        if app.owner_id and not app.owner_name:
            object_ids.append(app.owner_id)
    if not object_ids:
        return replace(
            environment,
            flow_owner_collection_status="complete",
            flow_owner_collection_error=None,
        )
    if not environment.dataverse_url:
        return environment
    try:
        users = client.list_system_users(environment.dataverse_url, token, object_ids)
    except PowerPlatformApiError as error:
        return replace(
            environment,
            flow_owner_collection_status=_status_for_error(error),
            flow_owner_collection_error=str(error),
        )
    directory = _directory(users)
    return replace(
        environment,
        apps=[_named_owner(app, directory) for app in environment.apps],
        flows=[_named_owner(flow, directory) for flow in environment.flows],
        flow_owner_collection_status="complete",
        flow_owner_collection_error=None,
    )


def _directory(users: list[dict[str, object]]) -> dict[str, tuple[str | None, str | None]]:
    directory: dict[str, tuple[str | None, str | None]] = {}
    for user in users:
        fullname = user.get("fullname") if isinstance(user.get("fullname"), str) else None
        email = (
            user.get("internalemailaddress")
            if isinstance(user.get("internalemailaddress"), str)
            else None
        )
        for key in ("systemuserid", "azureactivedirectoryobjectid"):
            value = user.get(key)
            if isinstance(value, str) and value:
                directory[value.casefold()] = (fullname, email)
    return directory


def _named_owner(resource, directory):
    if resource.owner_name or not resource.owner_id:
        return resource
    match = directory.get(resource.owner_id.casefold())
    if match is None:
        return resource
    name, email = match
    return replace(resource, owner_name=name, owner_email=email or resource.owner_email)


def _app_principal(item: dict[str, object]) -> AppPrincipal | None:
    properties = item.get("properties")
    if not isinstance(properties, dict):
        properties = {}
    principal = properties.get("principal")
    if not isinstance(principal, dict):
        principal = {}
    identifier = principal.get("id") or item.get("name")
    if not isinstance(identifier, str) or not identifier:
        return None
    display_name = principal.get("displayName")
    email = principal.get("email")
    principal_type = principal.get("type")
    role_name = properties.get("roleName")
    return AppPrincipal(
        id=identifier,
        display_name=display_name if isinstance(display_name, str) else None,
        email=email if isinstance(email, str) else None,
        principal_type=principal_type if isinstance(principal_type, str) else None,
        role_name=role_name if isinstance(role_name, str) else None,
    )


def _matching_owner(
    owner_id: str | None,
    principals: tuple[AppPrincipal, ...],
) -> AppPrincipal | None:
    if owner_id:
        for principal in principals:
            if principal.id.casefold() == owner_id.casefold():
                return principal
    for principal in principals:
        if (principal.role_name or "").casefold() == "owner":
            return principal
    return None


def _status_for_error(error: PowerPlatformApiError) -> str:
    if error.status_code == 404:
        return "unsupported"
    if error.status_code in (401, 403):
        return "permission_denied"
    return "failed"


def _guid_from_app_id(value: str) -> str:
    for candidate in (value, value.rstrip("/").rsplit("/", 1)[-1]):
        try:
            return str(UUID(candidate.strip("{}")))
        except ValueError:
            continue
    return ""
