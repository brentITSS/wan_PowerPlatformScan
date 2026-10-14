from dataclasses import replace

from ppscanner.client import PowerPlatformApiError
from ppscanner.collectors import (
    collect_app_managed_statuses,
    collect_app_permissions,
    collect_apps,
    collect_dataverse_inventory,
    collect_dlp_policies,
    collect_flows,
)
from ppscanner.models import CloudFlow, Environment, PowerApp


class FakeClient:
    def __init__(self, results):
        self.results = results
        self.requested_environments = []

    def list_apps(self, environment_id):
        self.requested_environments.append(environment_id)
        result = self.results[environment_id]
        if isinstance(result, Exception):
            raise result
        return result


def test_collect_apps_records_partial_permission_failure() -> None:
    visible = Environment.from_api(
        {"name": "env-visible", "properties": {"displayName": "Visible"}}
    )
    restricted = Environment.from_api(
        {"name": "env-restricted", "properties": {"displayName": "Restricted"}}
    )
    client = FakeClient(
        {
            "env-visible": [
                {
                    "name": "app-1",
                    "properties": {"displayName": "Visible app"},
                }
            ],
            "env-restricted": PowerPlatformApiError(
                "Power Platform API returned HTTP 403.", status_code=403
            ),
        }
    )

    results = collect_apps(client, [visible, restricted])

    assert client.requested_environments == ["env-visible", "env-restricted"]
    assert results[0].apps_collection_status == "complete"
    assert results[0].apps[0].display_name == "Visible app"
    assert results[0].apps[0].environment_id == "env-visible"
    assert results[1].apps_collection_status == "permission_denied"
    assert results[1].apps == []
    assert "403" in results[1].apps_collection_error


def test_collect_app_managed_statuses_sets_authoritative_flags() -> None:
    app_id = "11111111-1111-1111-1111-111111111111"
    environment = Environment.from_api(
        {
            "name": "env-1",
            "properties": {
                "displayName": "Dataverse environment",
                "linkedEnvironmentMetadata": {
                    "instanceUrl": "https://org.crm.dynamics.com/"
                },
            },
        }
    )
    environment = replace(
        environment,
        apps=[
            PowerApp.from_api(
                {"name": app_id, "properties": {"displayName": "Canvas app"}},
                environment_id="env-1",
            )
        ],
        apps_collection_status="complete",
    )

    class ManagedStatusClient:
        def list_app_managed_statuses(self, instance_url, token, app_ids):
            assert instance_url == "https://org.crm.dynamics.com"
            assert token == "dataverse-token"
            assert app_ids == [app_id]
            return {app_id: False}

    results = collect_app_managed_statuses(
        ManagedStatusClient(),
        [environment],
        lambda _: "dataverse-token",
    )

    assert results[0].apps[0].managed_status == "unmanaged"
    assert results[0].app_managed_status_collection_status == "complete"
    assert results[0].app_managed_status_collection_error is None


def test_collect_app_managed_statuses_reports_unmatched_apps_as_partial() -> None:
    app_id = "11111111-1111-1111-1111-111111111111"
    environment = Environment.from_api(
        {
            "name": "env-1",
            "properties": {
                "linkedEnvironmentMetadata": {
                    "instanceUrl": "https://org.crm.dynamics.com/"
                }
            },
        }
    )
    environment = replace(
        environment,
        apps=[PowerApp.from_api({"name": app_id})],
        apps_collection_status="complete",
    )

    class ManagedStatusClient:
        def list_app_managed_statuses(self, *_):
            return {}

    results = collect_app_managed_statuses(
        ManagedStatusClient(),
        [environment],
        lambda _: "dataverse-token",
    )

    assert results[0].apps[0].managed_status == "not_assessed"
    assert results[0].app_managed_status_collection_status == "partial"
    assert "0 of 1" in results[0].app_managed_status_collection_error


def test_collect_flows_records_missing_dataverse_as_unsupported() -> None:
    environment = Environment.from_api({"name": "env-1"})

    class FlowClient:
        def list_cloud_flows(self, environment_id, access_token):
            raise PowerPlatformApiError(
                "Power Platform API returned HTTP 404.",
                status_code=404,
            )

    results = collect_flows(FlowClient(), [environment], "flow-token")

    assert results[0].flows_collection_status == "unsupported"
    assert results[0].flows == []


def test_collect_flows_without_a_token_does_not_call_the_api() -> None:
    environment = Environment.from_api({"name": "env-1"})

    class FlowClient:
        def list_cloud_flows(self, environment_id, access_token):
            raise AssertionError("The flow API must not be called without a token.")

    results = collect_flows(FlowClient(), [environment], None, "Need consent")

    assert results[0].flows_collection_status == "permission_denied"
    assert results[0].flows_collection_error == "Need consent"


def test_app_permissions_store_owner_and_share_recipient_names() -> None:
    environment = replace(
        Environment.from_api({"name": "env-1", "properties": {"displayName": "Dev"}}),
        apps=[
            PowerApp.from_api(
                {
                    "name": "app-1",
                    "properties": {
                        "displayName": "Payroll",
                        "owner": {"id": "owner-1", "type": "User"},
                        "sharedUsersCount": 1,
                    },
                }
            )
        ],
        apps_collection_status="complete",
    )

    class PermissionClient:
        def list_app_permissions(self, environment_name, app_name):
            assert environment_name == "env-1"
            assert app_name == "app-1"
            return [
                {
                    "name": "owner-1",
                    "properties": {
                        "roleName": "Owner",
                        "principal": {
                            "id": "owner-1",
                            "displayName": "Ada Lovelace",
                            "email": "ada@contoso.com",
                            "type": "User",
                        },
                    },
                },
                {
                    "name": "user-2",
                    "properties": {
                        "roleName": "CanView",
                        "principal": {
                            "id": "user-2",
                            "displayName": "Grace Hopper",
                            "email": "grace@contoso.com",
                            "type": "User",
                        },
                        "createdBy": "do-not-keep",
                    },
                },
            ]

    results = collect_app_permissions(PermissionClient(), [environment])

    app = results[0].apps[0]
    assert app.owner_name == "Ada Lovelace"
    assert app.owner_email == "ada@contoso.com"
    assert app.permissions[1].display_name == "Grace Hopper"
    assert app.permissions[1].role_name == "CanView"
    assert not hasattr(app.permissions[1], "created_by")
    assert results[0].app_permissions_collection_status == "complete"


def test_flow_owner_name_comes_from_the_dataverse_user() -> None:
    environment = replace(
        Environment.from_api(
            {
                "name": "env-1",
                "properties": {
                    "linkedEnvironmentMetadata": {
                        "instanceUrl": "https://org.crm.dynamics.com/"
                    }
                },
            }
        ),
        flows=[
            CloudFlow.from_api(
                {
                    "workflowId": "22222222-2222-2222-2222-222222222222",
                    "name": "Nightly",
                    "ownerId": "11111111-1111-1111-1111-111111111111",
                }
            )
        ],
        flows_collection_status="complete",
        solutions_collection_status="complete",
        connection_references_collection_status="complete",
    )

    class DirectoryClient:
        def list_solutions(self, instance_url, token):
            return []

        def list_connection_references(self, instance_url, token):
            return []

        def list_solution_components(self, instance_url, token, object_ids):
            return []

        def list_system_users(self, instance_url, token, object_ids):
            assert "11111111-1111-1111-1111-111111111111" in object_ids
            return [
                {
                    "systemuserid": "11111111-1111-1111-1111-111111111111",
                    "fullname": "Ada Lovelace",
                    "internalemailaddress": "ada@contoso.com",
                }
            ]

    results = collect_dataverse_inventory(
        DirectoryClient(),
        [environment],
        lambda _: "dataverse-token",
    )

    assert results[0].flows[0].owner_name == "Ada Lovelace"
    assert results[0].flows[0].owner_email == "ada@contoso.com"


def test_collect_dataverse_inventory_reads_solutions_and_connection_references() -> None:
    environment = Environment.from_api(
        {
            "name": "env-1",
            "properties": {
                "linkedEnvironmentMetadata": {
                    "instanceUrl": "https://org.crm.dynamics.com/"
                }
            },
        }
    )

    class DataverseClient:
        def list_solutions(self, instance_url, token):
            return [
                {
                    "solutionid": "sol-1",
                    "uniquename": "Contoso",
                    "friendlyname": "Contoso",
                    "ismanaged": True,
                }
            ]

        def list_connection_references(self, instance_url, token):
            return [
                {
                    "connectionreferenceid": "ref-1",
                    "connectionreferencedisplayname": "SharePoint",
                    "connectorid": "/providers/Microsoft.PowerApps/apis/shared_sharepointonline",
                    "statecode": 0,
                }
            ]

    results = collect_dataverse_inventory(
        DataverseClient(),
        [environment],
        lambda _: "dataverse-token",
    )

    assert results[0].solutions_collection_status == "complete"
    assert results[0].solutions[0].managed_status == "managed"
    assert results[0].connection_references[0].connector_id.endswith(
        "shared_sharepointonline"
    )
    assert not hasattr(results[0].connection_references[0], "connectionsecret")


def test_solution_membership_marks_apps_outside_a_custom_solution() -> None:
    app_id = "11111111-1111-1111-1111-111111111111"
    flow_id = "22222222-2222-2222-2222-222222222222"
    solution_id = "33333333-3333-3333-3333-333333333333"
    environment = Environment.from_api(
        {
            "name": "env-1",
            "properties": {
                "linkedEnvironmentMetadata": {
                    "instanceUrl": "https://org.crm.dynamics.com/"
                }
            },
        }
    )
    environment = replace(
        environment,
        apps=[
            PowerApp.from_api(
                {"name": app_id, "properties": {"displayName": "Payroll"}},
                environment_id="env-1",
            )
        ],
        flows=[
            CloudFlow.from_api(
                {"workflowId": flow_id, "name": "Nightly", "stateCode": "Published"}
            )
        ],
    )

    class DataverseClient:
        def list_solutions(self, instance_url, token):
            return [
                {
                    "solutionid": solution_id,
                    "uniquename": "Default",
                    "friendlyname": "Default Solution",
                    "ismanaged": False,
                },
                {
                    "solutionid": "44444444-4444-4444-4444-444444444444",
                    "uniquename": "Contoso",
                    "friendlyname": "Contoso",
                    "ismanaged": False,
                },
            ]

        def list_connection_references(self, instance_url, token):
            return []

        def list_solution_components(self, instance_url, token, object_ids):
            assert app_id in object_ids
            assert flow_id in object_ids
            return [
                {
                    "objectid": app_id,
                    "componenttype": 300,
                    "_solutionid_value": solution_id,
                },
                {
                    "objectid": flow_id,
                    "componenttype": 29,
                    "_solutionid_value": "44444444-4444-4444-4444-444444444444",
                },
            ]

    results = collect_dataverse_inventory(
        DataverseClient(),
        [environment],
        lambda _: "dataverse-token",
    )

    assert results[0].apps[0].solution_membership == "default_solution_only"
    assert results[0].flows[0].solution_membership == "in_custom_solution"
    assert results[0].flows[0].managed_status == "unmanaged"
    assert results[0].flows[0].solution_names == "Contoso"


def test_collect_dlp_policies_marks_missing_connector_groups_partial() -> None:
    class DlpClient:
        def list_dlp_policies(self):
            return [{"policyDefinition": {"name": "policy-1", "displayName": "Tenant"}}]

        def get_dlp_policy(self, policy_id):
            raise PowerPlatformApiError("missing", status_code=404)

    policies, status, error = collect_dlp_policies(DlpClient())

    assert status == "partial"
    assert policies[0].id == "policy-1"
    assert policies[0].connectors_collected is False
    assert error is not None
