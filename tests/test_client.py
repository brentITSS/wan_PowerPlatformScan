import httpx
import pytest

from ppscanner.client import (
    ADMIN_API_BASE_URL,
    ADMIN_API_PATH,
    ADMIN_API_VERSION,
    DLP_API_PATH,
    PowerPlatformAdminClient,
    PowerPlatformApiError,
)


def test_list_environments_reads_all_pages() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "value": [{"name": "first"}],
                    "nextLink": f"{ADMIN_API_BASE_URL}{ADMIN_API_PATH}?page=2",
                },
            )
        return httpx.Response(200, json={"value": [{"name": "second"}]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        environments = client.list_environments()

    assert [item["name"] for item in environments] == ["first", "second"]
    assert requests[0].url.host == "api.bap.microsoft.com"
    assert requests[0].url.path == ADMIN_API_PATH
    assert requests[0].url.params["api-version"] == ADMIN_API_VERSION
    assert requests[0].url.params["$expand"] == "properties.capacity,properties.addons"
    assert requests[0].headers["Authorization"] == "Bearer admin-token"
    assert requests[1].url.params["api-version"] == ADMIN_API_VERSION
    assert requests[1].headers["Authorization"] == "Bearer admin-token"


def test_list_environments_rejects_unsafe_pagination_url() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"value": [], "nextLink": "https://attacker.example/steal"},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        with pytest.raises(PowerPlatformApiError, match="unsafe pagination URL"):
            client.list_environments()


def test_list_environments_rejects_missing_value() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        with pytest.raises(PowerPlatformApiError, match="did not contain"):
            client.list_environments()


def test_list_apps_reads_admin_apps_across_pages() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={"value": [{"name": "app-1"}], "nextLink": "?$skiptoken=page-2"},
            )
        return httpx.Response(200, json={"value": [{"name": "app-2"}]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        apps = client.list_apps("env-1")

    assert [item["name"] for item in apps] == ["app-1", "app-2"]
    assert requests[0].url.host == "api.powerplatform.com"
    assert requests[0].url.path == "/powerapps/environments/env-1/apps"
    assert requests[0].url.params["api-version"] == "2024-10-01"
    assert requests[0].headers["Authorization"] == "Bearer power-platform-token"
    assert requests[1].url.path == "/powerapps/environments/env-1/apps"
    assert requests[1].url.params["$skiptoken"] == "page-2"
    assert requests[1].url.params["api-version"] == "2024-10-01"


def test_list_app_managed_statuses_reads_canvas_and_model_driven_apps() -> None:
    requests: list[httpx.Request] = []
    canvas_id = "11111111-1111-1111-1111-111111111111"
    model_id = "22222222-2222-2222-2222-222222222222"

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/canvasapps"):
            return httpx.Response(
                200,
                json={"value": [{"canvasappid": canvas_id, "ismanaged": True}]},
            )
        return httpx.Response(
            200,
            json={"value": [{"appmoduleid": model_id, "ismanaged": False}]},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        statuses = client.list_app_managed_statuses(
            "https://org.crm.dynamics.com/",
            "dataverse-token",
            [
                f"/providers/Microsoft.PowerApps/apps/{canvas_id}",
                model_id,
            ],
        )

    assert statuses == {canvas_id: True, model_id: False}
    assert [request.url.path for request in requests] == [
        "/api/data/v9.2/canvasapps",
        "/api/data/v9.2/appmodules",
    ]
    assert all(
        request.headers["Authorization"] == "Bearer dataverse-token"
        for request in requests
    )
    assert "api-version" not in requests[0].url.params
    assert "canvasappid eq " + canvas_id in requests[0].url.params["$filter"]
    assert "appmoduleid eq " + model_id in requests[1].url.params["$filter"]


def test_list_app_managed_statuses_rejects_unsafe_dataverse_host() -> None:
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200))
    ) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        with pytest.raises(
            PowerPlatformApiError, match="invalid Dataverse instance URL"
        ):
            client.list_app_managed_statuses(
                "https://attacker.example/",
                "dataverse-token",
                ["11111111-1111-1111-1111-111111111111"],
            )


def test_list_cloud_flows_treats_no_content_as_an_empty_inventory() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/powerautomate/environments/env-1/cloudFlows"
        assert request.headers["Authorization"] == "Bearer flow-token"
        return httpx.Response(204)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        assert client.list_cloud_flows("env-1", "flow-token") == []


def test_list_solutions_reads_dataverse_without_personal_columns() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "solutionid": "sol-1",
                        "uniquename": "Contoso",
                        "ismanaged": False,
                    }
                ]
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        solutions = client.list_solutions("https://org.crm.dynamics.com", "dataverse-token")

    assert solutions[0]["uniquename"] == "Contoso"
    assert requests[0].url.path == "/api/data/v9.2/solutions"
    assert "api-version" not in requests[0].url.params
    assert "createdby" not in requests[0].url.params["$select"]
    assert "ismanaged" in requests[0].url.params["$select"]


def test_list_solution_components_filters_canvas_apps_and_flows() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"value": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        client.list_solution_components(
            "https://org.crm.dynamics.com",
            "dataverse-token",
            ["11111111-1111-1111-1111-111111111111"],
        )

    query = requests[0].url.params["$filter"]
    assert "componenttype eq 300" in query
    assert "componenttype eq 29" in query
    assert "objectid eq 11111111-1111-1111-1111-111111111111" in query


def test_list_app_permissions_uses_the_admin_role_assignment_route() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"value": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        client.list_app_permissions("Default-tenant", "app-1")

    assert requests[0].url.host == "api.powerapps.com"
    assert requests[0].url.path.endswith("/apps/app-1/permissions")
    assert requests[0].url.params["api-version"] == "2016-11-01"
    assert requests[0].url.params["$top"] == "250"
    assert requests[0].headers["Authorization"] == "Bearer admin-token"


def test_list_system_users_selects_name_and_email_only() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"value": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        client.list_system_users(
            "https://org.crm.dynamics.com",
            "dataverse-token",
            ["11111111-1111-1111-1111-111111111111"],
        )

    select = requests[0].url.params["$select"]
    query = requests[0].url.params["$filter"]
    assert "fullname" in select
    assert "internalemailaddress" in select
    assert "createdby" not in select
    assert "systemuserid eq 11111111-1111-1111-1111-111111111111" in query
    assert "azureactivedirectoryobjectid eq 11111111-1111-1111-1111-111111111111" in query


def test_environment_access_and_connections_use_admin_routes() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"value": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        client.list_environment_role_assignments("Default-tenant")
        client.list_connections("Default-tenant")
        client.list_connection_permissions("Default-tenant", "shared_sql", "conn-1")

    assert requests[0].url.path.endswith("/environments/Default-tenant/roleAssignments")
    assert requests[0].url.params["api-version"] == "2016-11-01"
    assert requests[1].url.host == "api.powerapps.com"
    assert requests[1].url.path.endswith("/connections")
    assert requests[2].url.path.endswith("/apis/shared_sql/connections/conn-1/permissions")


def test_list_dlp_policies_uses_the_admin_governance_route() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == DLP_API_PATH
        assert request.url.params["api-version"] == "2016-11-01"
        assert request.headers["Authorization"] == "Bearer admin-token"
        return httpx.Response(200, json={"value": [{"policyDefinition": {"name": "policy-1"}}]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = PowerPlatformAdminClient("power-platform-token", "admin-token", http)
        policies = client.list_dlp_policies()

    assert policies[0]["policyDefinition"]["name"] == "policy-1"
