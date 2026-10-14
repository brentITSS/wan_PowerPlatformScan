from collections.abc import Iterator
from typing import Self
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse
from uuid import UUID

import httpx

API_BASE_URL = "https://api.powerplatform.com"
POWER_APPS_API_BASE_URL = "https://api.powerapps.com"
APP_PERMISSIONS_API_VERSION = "2016-11-01"
API_PATH = "/environmentmanagement/environments"
API_VERSION = "2024-10-01"
ADMIN_API_BASE_URL = "https://api.bap.microsoft.com"
ADMIN_API_PATH = "/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments"
ADMIN_API_VERSION = "2020-10-01"
DLP_API_PATH = "/providers/PowerPlatform.Governance/v2/policies"
DLP_API_VERSION = "2016-11-01"


class PowerPlatformApiError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class PowerPlatformAdminClient:
    def __init__(
        self,
        power_platform_token: str,
        power_apps_service_token: str,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._power_platform_token = power_platform_token
        self._power_apps_service_token = power_apps_service_token
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
        )

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def list_environments(self) -> list[dict[str, object]]:
        url = f"{ADMIN_API_BASE_URL}{ADMIN_API_PATH}"
        environments = self._list_resources(
            url,
            "environment",
            self._power_apps_service_token,
            ADMIN_API_BASE_URL,
            ADMIN_API_VERSION,
            {
                "$expand": "properties.capacity,properties.addons",
            },
        )
        return environments

    def list_cloud_flows(
        self,
        environment_id: str,
        access_token: str,
    ) -> list[dict[str, object]]:
        encoded_environment_id = quote(environment_id, safe="")
        path = f"/powerautomate/environments/{encoded_environment_id}/cloudFlows"
        return self._list_resources(
            f"{API_BASE_URL}{path}",
            "cloud flow",
            access_token,
            API_BASE_URL,
            API_VERSION,
        )

    def list_solutions(
        self,
        instance_url: str,
        access_token: str,
    ) -> list[dict[str, object]]:
        base_url = self._validated_dataverse_base_url(instance_url)
        return self._list_resources(
            f"{base_url}/api/data/v9.2/solutions",
            "solution",
            access_token,
            base_url,
            "v9.2",
            {
                "$select": (
                    "solutionid,uniquename,friendlyname,version,"
                    "ismanaged,createdon,modifiedon"
                ),
            },
            dataverse=True,
        )

    def list_solution_components(
        self,
        instance_url: str,
        access_token: str,
        object_ids: list[str],
    ) -> list[dict[str, object]]:
        guids = [object_id for object_id in object_ids if object_id]
        if not guids:
            return []
        base_url = self._validated_dataverse_base_url(instance_url)
        components: list[dict[str, object]] = []
        type_filter = " or ".join(
            f"componenttype eq {component_type}" for component_type in (29, 80, 300)
        )
        for offset in range(0, len(guids), 20):
            id_filter = " or ".join(
                f"objectid eq {object_id}" for object_id in guids[offset : offset + 20]
            )
            components.extend(
                self._list_resources(
                    f"{base_url}/api/data/v9.2/solutioncomponents",
                    "solution component",
                    access_token,
                    base_url,
                    "v9.2",
                    {
                        "$select": "objectid,componenttype,_solutionid_value",
                        "$filter": f"({type_filter}) and ({id_filter})",
                    },
                    dataverse=True,
                )
            )
        return components

    def list_connection_references(
        self,
        instance_url: str,
        access_token: str,
    ) -> list[dict[str, object]]:
        base_url = self._validated_dataverse_base_url(instance_url)
        return self._list_resources(
            f"{base_url}/api/data/v9.2/connectionreferences",
            "connection reference",
            access_token,
            base_url,
            "v9.2",
            {
                "$select": (
                    "connectionreferenceid,connectionreferencelogicalname,"
                    "connectionreferencedisplayname,connectorid,statecode"
                ),
            },
            dataverse=True,
        )

    def list_dlp_policies(self) -> list[dict[str, object]]:
        return self._list_resources(
            f"{ADMIN_API_BASE_URL}{DLP_API_PATH}",
            "DLP policy",
            self._power_apps_service_token,
            ADMIN_API_BASE_URL,
            DLP_API_VERSION,
        )

    def get_dlp_policy(self, policy_id: str) -> dict[str, object]:
        encoded_policy_id = quote(policy_id, safe="")
        url = f"{ADMIN_API_BASE_URL}{DLP_API_PATH}/{encoded_policy_id}"
        payload = next(
            self._pages(
                url,
                self._power_apps_service_token,
                ADMIN_API_BASE_URL,
                DLP_API_VERSION,
            )
        )
        if not isinstance(payload, dict):
            raise PowerPlatformApiError("DLP policy detail was not an object.")
        return payload

    def list_apps(self, environment_id: str) -> list[dict[str, object]]:
        encoded_environment_id = quote(environment_id, safe="")
        path = f"/powerapps/environments/{encoded_environment_id}/apps"
        return self._list_resources(
            f"{API_BASE_URL}{path}",
            "app",
            self._power_platform_token,
            API_BASE_URL,
            API_VERSION,
        )

    def list_app_permissions(
        self,
        environment_name: str,
        app_name: str,
    ) -> list[dict[str, object]]:
        encoded_environment = quote(environment_name, safe="")
        encoded_app = quote(app_name, safe="")
        path = (
            "/providers/Microsoft.PowerApps/scopes/admin/environments/"
            f"{encoded_environment}/apps/{encoded_app}/permissions"
        )
        return self._list_resources(
            f"{POWER_APPS_API_BASE_URL}{path}",
            "app permission",
            self._power_apps_service_token,
            POWER_APPS_API_BASE_URL,
            APP_PERMISSIONS_API_VERSION,
            {"$top": "250"},
        )

    def list_environment_role_assignments(
        self,
        environment_name: str,
    ) -> list[dict[str, object]]:
        encoded_environment = quote(environment_name, safe="")
        path = f"{ADMIN_API_PATH}/{encoded_environment}/roleAssignments"
        return self._list_resources(
            f"{ADMIN_API_BASE_URL}{path}",
            "environment role assignment",
            self._power_apps_service_token,
            ADMIN_API_BASE_URL,
            "2016-11-01",
        )

    def list_connections(
        self,
        environment_name: str,
    ) -> list[dict[str, object]]:
        encoded_environment = quote(environment_name, safe="")
        path = (
            "/providers/Microsoft.PowerApps/scopes/admin/environments/"
            f"{encoded_environment}/connections"
        )
        return self._list_resources(
            f"{POWER_APPS_API_BASE_URL}{path}",
            "connection",
            self._power_apps_service_token,
            POWER_APPS_API_BASE_URL,
            APP_PERMISSIONS_API_VERSION,
        )

    def list_connection_permissions(
        self,
        environment_name: str,
        connector_name: str,
        connection_name: str,
    ) -> list[dict[str, object]]:
        encoded_environment = quote(environment_name, safe="")
        encoded_connector = quote(connector_name, safe="")
        encoded_connection = quote(connection_name, safe="")
        path = (
            "/providers/Microsoft.PowerApps/scopes/admin/environments/"
            f"{encoded_environment}/apis/{encoded_connector}/connections/"
            f"{encoded_connection}/permissions"
        )
        return self._list_resources(
            f"{POWER_APPS_API_BASE_URL}{path}",
            "connection permission",
            self._power_apps_service_token,
            POWER_APPS_API_BASE_URL,
            APP_PERMISSIONS_API_VERSION,
        )

    def list_system_users(
        self,
        instance_url: str,
        access_token: str,
        object_ids: list[str],
    ) -> list[dict[str, object]]:
        guids: list[str] = []
        for object_id in object_ids:
            normalized = _guid_from_identifier(object_id)
            if normalized and normalized not in guids:
                guids.append(normalized)
        if not guids:
            return []
        base_url = self._validated_dataverse_base_url(instance_url)
        users: list[dict[str, object]] = []
        for offset in range(0, len(guids), 15):
            clauses = []
            for object_id in guids[offset : offset + 15]:
                clauses.append(f"systemuserid eq {object_id}")
                clauses.append(f"azureactivedirectoryobjectid eq {object_id}")
            users.extend(
                self._list_resources(
                    f"{base_url}/api/data/v9.2/systemusers",
                    "system user",
                    access_token,
                    base_url,
                    "v9.2",
                    {
                        "$select": (
                            "systemuserid,fullname,internalemailaddress,"
                            "azureactivedirectoryobjectid"
                        ),
                        "$filter": " or ".join(clauses),
                    },
                    dataverse=True,
                )
            )
        return users

    def list_app_managed_statuses(
        self,
        instance_url: str,
        access_token: str,
        app_ids: list[str],
    ) -> dict[str, bool]:
        base_url = self._validated_dataverse_base_url(instance_url)
        normalized_ids = sorted(
            {
                normalized_id
                for app_id in app_ids
                if (normalized_id := _guid_from_identifier(app_id))
            }
        )
        if not normalized_ids:
            return {}

        statuses: dict[str, bool] = {}
        for collection, primary_key in (
            ("canvasapps", "canvasappid"),
            ("appmodules", "appmoduleid"),
        ):
            for offset in range(0, len(normalized_ids), 30):
                id_chunk = normalized_ids[offset : offset + 30]
                filter_expression = " or ".join(
                    f"{primary_key} eq {app_id}" for app_id in id_chunk
                )
                url = f"{base_url}/api/data/v9.2/{collection}"
                for payload in self._pages(
                    url,
                    access_token,
                    base_url,
                    "v9.2",
                    {
                        "$select": f"{primary_key},ismanaged",
                        "$filter": filter_expression,
                    },
                    dataverse=True,
                ):
                    values = payload.get("value")
                    if not isinstance(values, list) or not all(
                        isinstance(item, dict) for item in values
                    ):
                        raise PowerPlatformApiError(
                            "Dataverse returned an invalid managed-status response."
                        )
                    for item in values:
                        app_id = item.get(primary_key)
                        managed = item.get("ismanaged")
                        if not isinstance(app_id, str) or not isinstance(managed, bool):
                            raise PowerPlatformApiError(
                                "Dataverse returned an app without a valid managed status."
                            )
                        normalized_id = _guid_from_identifier(app_id)
                        if not normalized_id:
                            raise PowerPlatformApiError(
                                "Dataverse returned an app with an invalid identifier."
                            )
                        previous = statuses.get(normalized_id)
                        if previous is not None and previous != managed:
                            raise PowerPlatformApiError(
                                "Dataverse returned conflicting managed status for an app."
                            )
                        statuses[normalized_id] = managed
        return statuses

    def _list_resources(
        self,
        initial_url: str,
        resource_name: str,
        access_token: str,
        expected_base_url: str,
        api_version: str,
        initial_params: dict[str, str] | None = None,
        dataverse: bool = False,
    ) -> list[dict[str, object]]:
        environments: list[dict[str, object]] = []
        for payload in self._pages(
            initial_url,
            access_token,
            expected_base_url,
            api_version,
            initial_params,
            dataverse=dataverse,
        ):
            value = payload.get("value")
            if not isinstance(value, list):
                raise PowerPlatformApiError(
                    f"The Power Platform API response did not contain a {resource_name} list."
                )
            if not all(isinstance(item, dict) for item in value):
                raise PowerPlatformApiError(
                    f"The Power Platform API returned an invalid {resource_name} entry."
                )
            environments.extend(value)
        return environments

    def _pages(
        self,
        initial_url: str,
        access_token: str,
        expected_base_url: str,
        api_version: str,
        initial_params: dict[str, str] | None = None,
        dataverse: bool = False,
    ) -> Iterator[dict[str, object]]:
        url = initial_url
        expected_host = urlparse(expected_base_url).netloc.lower()
        params: dict[str, str] | None = (
            dict(initial_params or {})
            if dataverse
            else {"api-version": api_version, **(initial_params or {})}
        )
        while url:
            parsed = urlparse(url)
            if (
                parsed.scheme != "https"
                or parsed.netloc.lower() != expected_host
                or parsed.username
                or parsed.password
            ):
                raise PowerPlatformApiError(
                    "The Power Platform API returned an unsafe pagination URL; "
                    "refusing to send the access token."
                )

            try:
                response = self._http.get(
                    url,
                    params=params,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json",
                        **(
                            {
                                "OData-Version": "4.0",
                                "OData-MaxVersion": "4.0",
                                "Prefer": "odata.maxpagesize=5000",
                            }
                            if dataverse
                            else {}
                        ),
                    },
                )
                response.raise_for_status()
            except httpx.HTTPStatusError as error:
                hint = ""
                if (
                    error.response.status_code == 403
                    and expected_host == "api.bap.microsoft.com"
                ):
                    hint = (
                        " The signed-in user needs a directly assigned Power "
                        "Platform Administrator, Dynamics 365 Administrator, "
                        "or Global Administrator role."
                    )
                elif dataverse and error.response.status_code in (401, 403):
                    hint = (
                        " Check Dynamics CRM delegated user_impersonation consent "
                        "and the signed-in user's Dataverse read privileges."
                    )
                raise PowerPlatformApiError(
                    f"{'Dataverse' if dataverse else 'Power Platform API'} "
                    f"returned HTTP {error.response.status_code} "
                    f"for {error.request.url.path}.{hint}",
                    status_code=error.response.status_code,
                ) from error
            except httpx.RequestError as error:
                raise PowerPlatformApiError(
                    f"Could not reach the Power Platform API: {error}."
                ) from error

            if response.status_code == 204:
                payload = {"value": []}
            else:
                try:
                    payload = response.json()
                except ValueError as error:
                    raise PowerPlatformApiError(
                        "The Power Platform API returned invalid JSON."
                    ) from error
            if not isinstance(payload, dict):
                raise PowerPlatformApiError(
                    "The Power Platform API returned an unexpected response."
                )

            yield payload
            next_url = (
                payload.get("@odata.nextlink")
                or payload.get("@odata.nextLink")
                or payload.get("nextLink")
            )
            if next_url is not None and not isinstance(next_url, str):
                raise PowerPlatformApiError(
                    "The Power Platform API returned an invalid pagination URL."
                )
            if next_url:
                url = urljoin(str(response.request.url), next_url)
                parsed_next = urlparse(url)
                query = dict(parse_qsl(parsed_next.query, keep_blank_values=True))
                if not dataverse and "api-version" not in query:
                    query["api-version"] = api_version
                url = urlunparse(
                    parsed_next._replace(query=urlencode(query, doseq=True))
                )
            else:
                url = ""
            params = None

    @staticmethod
    def _validated_dataverse_base_url(instance_url: str) -> str:
        try:
            parsed = urlparse(instance_url)
            port = parsed.port
        except ValueError as error:
            raise PowerPlatformApiError(
                "The environment returned an invalid Dataverse instance URL."
            ) from error
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
            raise PowerPlatformApiError(
                "The environment returned an invalid Dataverse instance URL."
            )
        return f"https://{parsed.netloc}"


def _guid_from_identifier(value: str) -> str:
    candidates = (value, value.rstrip("/").rsplit("/", 1)[-1])
    for candidate in candidates:
        try:
            return str(UUID(candidate.strip("{}")))
        except ValueError:
            continue
    return ""
