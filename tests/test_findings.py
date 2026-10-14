from dataclasses import replace

from ppscanner.findings import evaluate_findings
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


def _production() -> Environment:
    return Environment.from_api(
        {
            "id": "env-prod",
            "name": "env-prod",
            "properties": {"displayName": "Production", "environmentSku": "Production"},
        }
    )


def test_unmanaged_production_app_is_confirmed_and_unknown_is_not() -> None:
    unmanaged = replace(
        PowerApp.from_api({"name": "app-1", "properties": {"displayName": "Payroll"}}),
        managed_status="unmanaged",
    )
    unknown = replace(
        PowerApp.from_api({"name": "app-2", "properties": {"displayName": "Other"}}),
        managed_status="not_assessed",
    )
    environment = replace(_production(), apps=[unmanaged, unknown])

    findings = evaluate_findings([environment], [], "failed", "2026-10-14T00:00:00Z")
    rule_ids = [finding.rule_id for finding in findings]

    unmanaged_findings = [
        finding
        for finding in findings
        if finding.rule_id == "PP-APP-UNMANAGED-PRODUCTION"
    ]
    assert [finding.resource_id for finding in unmanaged_findings] == ["app-1"]
    assert unmanaged_findings[0].status == "confirmed"
    assert unmanaged_findings[0].severity == "high"
    assert "PP-ENV-NO-DLP" not in rule_ids


def test_app_outside_a_custom_solution_is_confirmed() -> None:
    outside = replace(
        PowerApp.from_api({"name": "app-1", "properties": {"displayName": "Payroll"}}),
        solution_membership="not_in_solution",
    )
    environment = replace(_production(), apps=[outside])

    findings = evaluate_findings([environment], [], "not_collected", None)
    matches = [
        finding for finding in findings if finding.rule_id == "PP-APP-NOT-IN-SOLUTION"
    ]

    assert len(matches) == 1
    assert matches[0].status == "confirmed"
    assert matches[0].severity == "high"
    assert "custom solution" in matches[0].recommendation.casefold()


def test_consumer_share_is_high_and_a_colleague_is_not() -> None:
    shared = replace(
        PowerApp.from_api(
            {
                "name": "app-1",
                "properties": {
                    "displayName": "Journal",
                    "owner": {"id": "owner-1"},
                    "sharedUsersCount": 6,
                },
            }
        ),
        owner_email="brent@contoso.com",
        permissions_collection_status="complete",
        permissions=(
            AppPrincipal("owner-1", "Brent", "brent@contoso.com", "User", "Owner"),
            AppPrincipal("guest-1", "diane@gmail.com", "diane@gmail.com", "User", "CanView"),
            AppPrincipal("colleague-1", "Ana", "ana@contoso.com", "User", "CanView"),
        ),
    )
    environment = replace(_production(), apps=[shared])

    findings = evaluate_findings([environment], [], "not_collected", "2026-10-14T00:00:00Z")
    external = [
        finding for finding in findings if finding.rule_id == "PP-APP-EXTERNAL-SHARE"
    ]
    incomplete = [
        finding for finding in findings if finding.rule_id == "PP-APP-SHARE-LIST-INCOMPLETE"
    ]

    assert len(external) == 1
    assert external[0].severity == "high"
    assert "diane@gmail.com" in external[0].summary
    assert incomplete[0].evidence.startswith("The app inventory reports 6 shared users.")


def test_default_environment_with_an_unmaintained_app_is_flagged() -> None:
    app = replace(
        PowerApp.from_api(
            {
                "name": "app-1",
                "properties": {
                    "displayName": "Maths",
                    "lastModifiedTime": "2020-06-20T00:00:00Z",
                },
            }
        ),
        solution_membership="not_in_solution",
    )
    flow = replace(
        CloudFlow.from_api(
            {
                "workflowId": "flow-1",
                "name": "adaptiveCard_BP",
                "stateCode": "Published",
            }
        ),
        managed_status="unmanaged",
        solution_membership="default_solution_only",
    )
    environment = replace(
        Environment.from_api(
            {
                "name": "default",
                "properties": {
                    "displayName": "Default",
                    "environmentSku": "Default",
                    "isDefault": True,
                    "governanceConfiguration": {"protectionLevel": "Basic"},
                },
            }
        ),
        apps=[app],
        flows=[flow],
        role_assignments_collection_status="complete",
        role_assignments=[
            EnvironmentRoleAssignment(
                "role-1",
                "EnvironmentMaker",
                "maker-1",
                "A maker",
                "maker@contoso.com",
                "User",
            )
        ],
    )

    findings = evaluate_findings([environment], [], "not_collected", "2026-10-14T00:00:00Z")
    rule_ids = {finding.rule_id for finding in findings}

    assert "PP-ENV-DEFAULT-WORKLOAD" in rule_ids
    assert "PP-ENV-NOT-MANAGED" in rule_ids
    assert "PP-ENV-DEFAULT-MAKERS" in rule_ids
    assert "PP-APP-STALE" in rule_ids
    assert "PP-FLOW-PUBLISHED-UNMANAGED-DEFAULT" in rule_ids


def test_connection_record_omits_parameters_and_flags_a_share() -> None:
    connection = Connection.from_api(
        {
            "name": "conn-1",
            "properties": {
                "displayName": "SQL",
                "apiId": "/providers/Microsoft.PowerApps/apis/shared_sql",
                "createdBy": {"id": "owner-1", "displayName": "Brent"},
                "connectionParameters": {"password": "do-not-store"},
                "statuses": [{"status": "Connected"}],
            },
        }
    )
    assert not hasattr(connection, "connection_parameters")
    assert "do-not-store" not in repr(connection)
    shared = replace(
        connection,
        shares=(AppPrincipal("user-2", "Ana", "ana@contoso.com", "User", "CanView"),),
    )
    environment = replace(
        _production(),
        connections=[shared],
        connections_collection_status="complete",
    )

    findings = evaluate_findings([environment], [], "not_collected", None)
    matches = [finding for finding in findings if finding.rule_id == "PP-CONN-SHARED"]

    assert len(matches) == 1
    assert matches[0].severity == "medium"


def test_platform_solutions_are_not_flagged_as_custom_unmanaged() -> None:
    environment = replace(
        _production(),
        solutions=[
            Solution.from_api(
                {
                    "solutionid": "default",
                    "uniquename": "Default",
                    "friendlyname": "Default Solution",
                    "ismanaged": False,
                }
            ),
            Solution.from_api(
                {
                    "solutionid": "custom",
                    "uniquename": "Contoso_Payroll",
                    "friendlyname": "Payroll",
                    "ismanaged": False,
                }
            ),
        ],
        solutions_collection_status="complete",
    )

    findings = evaluate_findings([environment], [], "not_collected", None)
    matches = [
        finding
        for finding in findings
        if finding.rule_id == "PP-SOL-UNMANAGED-PRODUCTION"
    ]

    assert [finding.resource_name for finding in matches] == ["Payroll"]


def test_blocked_connector_matches_an_applicable_policy() -> None:
    environment = replace(
        _production(),
        connection_references=[
            ConnectionReference.from_api(
                {
                    "connectionreferenceid": "ref-1",
                    "connectionreferencedisplayname": "SharePoint",
                    "connectorid": "shared_sharepointonline",
                }
            )
        ],
        connection_references_collection_status="complete",
    )
    policy = DlpPolicy.from_api(
        {
            "policyDefinition": {
                "name": "policy-1",
                "displayName": "Tenant policy",
                "environmentType": "AllEnvironments",
                "connectorGroups": [
                    {
                        "classification": "Blocked",
                        "connectors": [
                            {
                                "id": "/providers/Microsoft.PowerApps/apis/shared_sharepointonline",
                                "name": "shared_sharepointonline",
                                "type": "Microsoft.PowerApps/apis",
                            }
                        ],
                    }
                ],
            }
        }
    )

    findings = evaluate_findings([environment], [policy], "complete", None)

    blocked = [
        finding for finding in findings if finding.rule_id == "PP-CONN-BLOCKED-BY-DLP"
    ]
    assert len(blocked) == 1
    assert blocked[0].status == "confirmed"
    assert all(finding.rule_id != "PP-ENV-NO-DLP" for finding in findings)


def test_unknown_dlp_scope_does_not_claim_an_environment_is_uncovered() -> None:
    policy = DlpPolicy.from_api(
        {
            "policyDefinition": {
                "name": "policy-1",
                "displayName": "Legacy",
                "environmentType": "SingleEnvironment",
            }
        }
    )

    findings = evaluate_findings([_production()], [policy], "partial", None)

    assert [finding.rule_id for finding in findings] == ["PP-DLP-SCOPE-UNKNOWN"]
    assert findings[0].status == "not_assessable"
