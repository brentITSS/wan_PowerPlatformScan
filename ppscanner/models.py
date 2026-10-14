from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse


def _optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _managed_environment(properties: dict[str, Any]) -> str | None:
    governance = properties.get("governanceConfiguration")
    if not isinstance(governance, dict):
        return None
    level = governance.get("protectionLevel")
    if not isinstance(level, str):
        return None
    normalized = level.casefold()
    if normalized == "standard":
        return "enabled"
    if normalized == "basic":
        return "disabled"
    return level


def _environment_sku(item: dict[str, Any], properties: dict[str, Any]) -> str | None:
    sku = _optional_text(properties.get("environmentSku"))
    if sku:
        return sku
    resource_type = _optional_text(item.get("type"))
    if resource_type and resource_type.startswith("Microsoft."):
        return None
    return resource_type


def _status_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def _nested_text(value: Any, *keys: str) -> str | None:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return _optional_text(current)


def _dataverse_url(properties: dict[str, Any]) -> str | None:
    metadata = properties.get("linkedEnvironmentMetadata")
    if not isinstance(metadata, dict):
        return None
    url = _optional_text(metadata.get("instanceUrl"))
    if url is None:
        return None
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or port
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or not parsed.hostname.lower().endswith(
            (".dynamics.com", ".dynamics.us", ".dynamics.cn")
        )
    ):
        return None
    return f"https://{parsed.netloc}"


@dataclass(frozen=True)
class Environment:
    id: str
    name: str
    display_name: str | None
    location: str | None
    region: str | None
    created_time: str | None
    last_modified_time: str | None
    state: str | None
    environment_sku: str | None
    is_default: bool | None
    database_type: str | None
    management_state: str | None
    runtime_state: str | None
    dataverse_url: str | None
    apps: list["PowerApp"]
    apps_collection_status: str
    apps_collection_error: str | None
    app_managed_status_collection_status: str
    app_managed_status_collection_error: str | None
    flows: list["CloudFlow"]
    flows_collection_status: str
    flows_collection_error: str | None
    solutions: list["Solution"]
    solutions_collection_status: str
    solutions_collection_error: str | None
    connection_references: list["ConnectionReference"]
    connection_references_collection_status: str
    connection_references_collection_error: str | None
    solution_membership_collection_status: str
    solution_membership_collection_error: str | None
    app_permissions_collection_status: str
    app_permissions_collection_error: str | None
    flow_owner_collection_status: str
    flow_owner_collection_error: str | None
    managed_environment: str | None
    role_assignments: list["EnvironmentRoleAssignment"]
    role_assignments_collection_status: str
    role_assignments_collection_error: str | None
    connections: list["Connection"]
    connections_collection_status: str
    connections_collection_error: str | None

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> "Environment":
        properties = item.get("properties")
        if not isinstance(properties, dict):
            properties = {}

        return cls(
            id=str(item.get("id") or item.get("name") or ""),
            name=str(item.get("name") or ""),
            display_name=_optional_text(
                item.get("displayName") or properties.get("displayName")
            ),
            location=_optional_text(item.get("location") or item.get("geo")),
            region=_optional_text(
                item.get("azureRegion") or properties.get("azureRegion")
            ),
            created_time=_optional_text(
                item.get("createdDateTime") or properties.get("createdTime")
            ),
            last_modified_time=_optional_text(
                item.get("lastModifiedTime") or properties.get("lastModifiedTime")
            ),
            state=_optional_text(
                item.get("state") or properties.get("provisioningState")
            ),
            environment_sku=_environment_sku(item, properties),
            is_default=(
                properties.get("isDefault")
                if isinstance(properties.get("isDefault"), bool)
                else None
            ),
            database_type=_optional_text(
                item.get("databaseType") or properties.get("databaseType")
            ),
            management_state=_nested_text(properties, "states", "management", "id"),
            runtime_state=_nested_text(properties, "states", "runtime", "id"),
            dataverse_url=_dataverse_url(properties),
            apps=[],
            apps_collection_status="not_collected",
            apps_collection_error=None,
            app_managed_status_collection_status="not_collected",
            app_managed_status_collection_error=None,
            flows=[],
            flows_collection_status="not_collected",
            flows_collection_error=None,
            solutions=[],
            solutions_collection_status="not_collected",
            solutions_collection_error=None,
            connection_references=[],
            connection_references_collection_status="not_collected",
            connection_references_collection_error=None,
            solution_membership_collection_status="not_collected",
            solution_membership_collection_error=None,
            app_permissions_collection_status="not_collected",
            app_permissions_collection_error=None,
            flow_owner_collection_status="not_collected",
            flow_owner_collection_error=None,
            managed_environment=_managed_environment(properties),
            role_assignments=[],
            role_assignments_collection_status="not_collected",
            role_assignments_collection_error=None,
            connections=[],
            connections_collection_status="not_collected",
            connections_collection_error=None,
        )


@dataclass(frozen=True)
class AppPrincipal:
    id: str
    display_name: str | None
    email: str | None
    principal_type: str | None
    role_name: str | None


@dataclass(frozen=True)
class PowerApp:
    id: str
    name: str
    display_name: str | None
    app_type: str | None
    created_time: str | None
    last_modified_time: str | None
    owner_id: str | None
    owner_type: str | None
    owner_name: str | None
    owner_email: str | None
    shared_groups_count: int | None
    shared_users_count: int | None
    environment_id: str | None
    managed_status: str
    solution_membership: str
    solution_names: str | None
    permissions: tuple[AppPrincipal, ...]
    permissions_collection_status: str
    permissions_collection_error: str | None

    @classmethod
    def from_api(
        cls,
        item: dict[str, Any],
        environment_id: str | None = None,
    ) -> "PowerApp":
        properties = item.get("properties")
        if not isinstance(properties, dict):
            properties = {}
        owner = properties.get("owner")
        if not isinstance(owner, dict):
            owner = {}
        environment = properties.get("environment")
        if not isinstance(environment, dict):
            environment = {}

        return cls(
            id=str(item.get("id") or item.get("name") or ""),
            name=str(item.get("name") or ""),
            display_name=_optional_text(properties.get("displayName")),
            app_type=_optional_text(item.get("type")),
            created_time=_optional_text(properties.get("createdTime")),
            last_modified_time=_optional_text(properties.get("lastModifiedTime")),
            owner_id=_optional_text(owner.get("id")),
            owner_type=_optional_text(owner.get("type")),
            owner_name=None,
            owner_email=None,
            shared_groups_count=_optional_int(properties.get("sharedGroupsCount")),
            shared_users_count=_optional_int(properties.get("sharedUsersCount")),
            environment_id=(
                environment_id
                or _optional_text(environment.get("id") or environment.get("name"))
            ),
            managed_status="not_assessed",
            solution_membership="not_collected",
            solution_names=None,
            permissions=(),
            permissions_collection_status="not_collected",
            permissions_collection_error=None,
        )


@dataclass(frozen=True)
class CloudFlow:
    id: str
    name: str
    display_name: str | None
    state: str | None
    status: str | None
    created_time: str | None
    last_modified_time: str | None
    owner_id: str | None
    owner_name: str | None
    owner_email: str | None
    environment_id: str | None
    managed_status: str
    solution_membership: str
    solution_names: str | None

    @classmethod
    def from_api(
        cls,
        item: dict[str, Any],
        environment_id: str | None = None,
    ) -> "CloudFlow":
        workflow_id = _optional_text(item.get("workflowId")) or _optional_text(
            item.get("id")
        )
        unique_name = _optional_text(item.get("uniqueName"))
        display_name = _optional_text(item.get("name"))
        identifier = workflow_id or unique_name or display_name or ""
        return cls(
            id=identifier,
            name=unique_name or identifier,
            display_name=display_name,
            state=_status_text(item.get("stateCode")),
            status=_status_text(item.get("statusCode")),
            created_time=_optional_text(item.get("createdOn") or item.get("createdTime")),
            last_modified_time=_optional_text(
                item.get("modifiedOn") or item.get("lastModifiedTime")
            ),
            owner_id=_optional_text(item.get("ownerId")),
            owner_name=None,
            owner_email=None,
            environment_id=environment_id,
            managed_status="not_assessed",
            solution_membership="not_collected",
            solution_names=None,
        )


@dataclass(frozen=True)
class Solution:
    id: str
    unique_name: str
    display_name: str | None
    version: str | None
    managed_status: str
    created_time: str | None
    last_modified_time: str | None
    environment_id: str | None

    @classmethod
    def from_api(
        cls,
        item: dict[str, Any],
        environment_id: str | None = None,
    ) -> "Solution":
        managed = item.get("ismanaged")
        if managed is True:
            managed_status = "managed"
        elif managed is False:
            managed_status = "unmanaged"
        else:
            managed_status = "not_assessed"
        return cls(
            id=str(item.get("solutionid") or ""),
            unique_name=str(item.get("uniquename") or ""),
            display_name=_optional_text(item.get("friendlyname")),
            version=_optional_text(item.get("version")),
            managed_status=managed_status,
            created_time=_optional_text(item.get("createdon")),
            last_modified_time=_optional_text(item.get("modifiedon")),
            environment_id=environment_id,
        )


@dataclass(frozen=True)
class EnvironmentRoleAssignment:
    id: str
    role_name: str | None
    principal_id: str | None
    principal_name: str | None
    principal_email: str | None
    principal_type: str | None

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> "EnvironmentRoleAssignment":
        properties = item.get("properties")
        if not isinstance(properties, dict):
            properties = {}
        principal = properties.get("principal")
        if not isinstance(principal, dict):
            principal = {}
        role = properties.get("roleDefinition")
        if not isinstance(role, dict):
            role = {}
        role_id = _optional_text(role.get("id")) or ""
        return cls(
            id=str(item.get("name") or item.get("id") or ""),
            role_name=role_id.rstrip("/").rsplit("/", 1)[-1] or None,
            principal_id=_optional_text(principal.get("id")),
            principal_name=_optional_text(principal.get("displayName")),
            principal_email=_optional_text(principal.get("email")),
            principal_type=_optional_text(principal.get("type")),
        )


@dataclass(frozen=True)
class Connection:
    id: str
    name: str
    display_name: str | None
    connector_id: str | None
    status: str | None
    owner_id: str | None
    owner_name: str | None
    owner_email: str | None
    environment_id: str | None
    shares: tuple[AppPrincipal, ...]

    @classmethod
    def from_api(
        cls,
        item: dict[str, Any],
        environment_id: str | None = None,
    ) -> "Connection":
        properties = item.get("properties")
        if not isinstance(properties, dict):
            properties = {}
        created_by = properties.get("createdBy")
        if not isinstance(created_by, dict):
            created_by = {}
        statuses = properties.get("statuses")
        status = None
        if isinstance(statuses, list):
            for entry in statuses:
                if isinstance(entry, dict) and isinstance(entry.get("status"), str):
                    status = entry["status"]
                    break
        return cls(
            id=str(item.get("id") or item.get("name") or ""),
            name=str(item.get("name") or ""),
            display_name=_optional_text(properties.get("displayName")),
            connector_id=_optional_text(properties.get("apiId")),
            status=status,
            owner_id=_optional_text(created_by.get("id")),
            owner_name=_optional_text(created_by.get("displayName")),
            owner_email=_optional_text(
                created_by.get("email") or created_by.get("userPrincipalName")
            ),
            environment_id=environment_id,
            shares=(),
        )


@dataclass(frozen=True)
class ConnectionReference:
    id: str
    logical_name: str | None
    display_name: str | None
    connector_id: str | None
    state_code: int | None
    environment_id: str | None

    @classmethod
    def from_api(
        cls,
        item: dict[str, Any],
        environment_id: str | None = None,
    ) -> "ConnectionReference":
        return cls(
            id=str(item.get("connectionreferenceid") or ""),
            logical_name=_optional_text(item.get("connectionreferencelogicalname")),
            display_name=_optional_text(item.get("connectionreferencedisplayname")),
            connector_id=_optional_text(item.get("connectorid")),
            state_code=_optional_int(item.get("statecode")),
            environment_id=environment_id,
        )


@dataclass(frozen=True)
class DlpConnector:
    id: str
    name: str | None
    classification: str


@dataclass(frozen=True)
class DlpPolicy:
    id: str
    display_name: str | None
    environment_type: str | None
    environment_ids: list[str]
    default_classification: str | None
    connectors: list[DlpConnector]
    connectors_collected: bool
    created_time: str | None
    last_modified_time: str | None

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> "DlpPolicy":
        definition = item.get("policyDefinition")
        if not isinstance(definition, dict):
            definition = item
        environment_ids: list[str] = []
        environments = definition.get("environments")
        if isinstance(environments, list):
            for environment in environments:
                if isinstance(environment, dict):
                    name = _optional_text(environment.get("name"))
                    if name:
                        environment_ids.append(name)
        groups = definition.get("connectorGroups")
        connectors: list[DlpConnector] = []
        if isinstance(groups, list):
            for group in groups:
                if not isinstance(group, dict):
                    continue
                classification = _optional_text(group.get("classification")) or "Unknown"
                members = group.get("connectors")
                if not isinstance(members, list):
                    continue
                for member in members:
                    if not isinstance(member, dict):
                        continue
                    connector_id = _optional_text(member.get("id") or member.get("name"))
                    if connector_id:
                        connectors.append(
                            DlpConnector(
                                id=connector_id,
                                name=_optional_text(member.get("name")),
                                classification=classification,
                            )
                        )
        policy_id = (
            _optional_text(definition.get("name"))
            or _optional_text(item.get("name"))
            or ""
        )
        return cls(
            id=policy_id,
            display_name=_optional_text(definition.get("displayName")),
            environment_type=_optional_text(definition.get("environmentType")),
            environment_ids=environment_ids,
            default_classification=_optional_text(
                definition.get("defaultConnectorsClassification")
            ),
            connectors=connectors,
            connectors_collected=isinstance(groups, list),
            created_time=_optional_text(definition.get("createdTime")),
            last_modified_time=_optional_text(definition.get("lastModifiedTime")),
        )

    def applies_to(self, environment_name: str, environment_id: str) -> bool | None:
        kind = (self.environment_type or "").strip()
        identifiers = {
            value
            for value in (
                environment_name,
                environment_id,
                environment_id.rstrip("/").rsplit("/", 1)[-1],
            )
            if value
        }
        listed = set(self.environment_ids)
        if kind == "AllEnvironments":
            return True
        if kind == "OnlyEnvironments":
            return bool(identifiers & listed)
        if kind == "ExceptEnvironments":
            return not bool(identifiers & listed)
        return None


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str
    rule_version: str
    category: str
    severity: str
    confidence: str
    status: str
    environment_id: str | None
    environment_name: str | None
    resource_id: str | None
    resource_name: str | None
    resource_type: str | None
    evidence: str
    source: str
    observed_at: str | None
    summary: str
    recommendation: str
    guidance_url: str | None


@dataclass(frozen=True)
class Snapshot:
    snapshot_id: str
    tenant_id: str
    scanner_version: str
    started_at: str
    completed_at: str
    source_api: str
    source_api_status: str
    environments: list[Environment]
    environment_scope: str
    environment_collection_status: str
    app_source_api: str
    app_source_api_status: str
    flow_source_api: str
    flow_source_api_status: str
    solution_source_api: str
    connection_reference_source_api: str
    dlp_source_api: str
    dlp_source_api_status: str
    dlp_policies: list[DlpPolicy]
    dlp_collection_status: str
    dlp_collection_error: str | None
    findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        total_apps = sum(len(environment.apps) for environment in self.environments)
        total_flows = sum(len(environment.flows) for environment in self.environments)
        total_solutions = sum(
            len(environment.solutions) for environment in self.environments
        )
        complete_app_environments = sum(
            environment.apps_collection_status == "complete"
            for environment in self.environments
        )
        complete_flow_environments = sum(
            environment.flows_collection_status == "complete"
            for environment in self.environments
        )
        complete_solution_environments = sum(
            environment.solutions_collection_status == "complete"
            for environment in self.environments
        )
        return {
            "snapshot_id": self.snapshot_id,
            "tenant_id": self.tenant_id,
            "scanner_version": self.scanner_version,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "source_api": self.source_api,
            "source_api_status": self.source_api_status,
            "environment_scope": self.environment_scope,
            "environment_collection_status": self.environment_collection_status,
            "app_source_api": self.app_source_api,
            "app_source_api_status": self.app_source_api_status,
            "managed_status_source_api": (
                "Dataverse Web API v9.2 canvasapp.ismanaged and appmodule.ismanaged"
            ),
            "environment_count": len(self.environments),
            "app_count": total_apps,
            "app_environment_coverage": {
                "complete": complete_app_environments,
                "total": len(self.environments),
            },
            "flow_source_api": self.flow_source_api,
            "flow_source_api_status": self.flow_source_api_status,
            "flow_managed_status_source_api": (
                "Cloud flow managed status is read from Dataverse "
                "solution.ismanaged for Workflow solution components (type 29). "
                "Flows that are not in a solution remain not assessed."
            ),
            "solution_membership_source_api": (
                "Dataverse Web API v9.2 solutioncomponent for Canvas App (300), "
                "App Module (80), and Workflow (29)"
            ),
            "flow_count": total_flows,
            "flow_environment_coverage": {
                "complete": complete_flow_environments,
                "total": len(self.environments),
            },
            "solution_source_api": self.solution_source_api,
            "solution_count": total_solutions,
            "solution_environment_coverage": {
                "complete": complete_solution_environments,
                "total": len(self.environments),
            },
            "app_permissions_source_api": (
                "Power Apps admin Get App Role Assignments "
                "(api.powerapps.com permissions, API version 2016-11-01). "
                "Owner and share-recipient display name and email only."
            ),
            "flow_owner_source_api": (
                "Dataverse Web API v9.2 systemuser fullname and internalemailaddress"
            ),
            "connection_reference_source_api": self.connection_reference_source_api,
            "dlp_source_api": self.dlp_source_api,
            "dlp_source_api_status": self.dlp_source_api_status,
            "dlp_collection_status": self.dlp_collection_status,
            "dlp_collection_error": self.dlp_collection_error,
            "dlp_policy_count": len(self.dlp_policies),
            "dlp_policies": [asdict(policy) for policy in self.dlp_policies],
            "finding_count": len(self.findings),
            "findings": [asdict(finding) for finding in self.findings],
            "environments": [asdict(environment) for environment in self.environments],
        }
