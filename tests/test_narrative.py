from ppscanner.narrative import build_sections


def test_report_recommends_from_custom_solutions_and_missing_data_policy() -> None:
    sections = {
        section.title: section
        for section in build_sections(
            {
                "dlp_collection_status": "complete",
                "dlp_policy_count": 0,
                "dlp_policies": [],
                "findings": [
                    {
                        "severity": "high",
                        "status": "confirmed",
                        "environment_name": "ITSS_DEV",
                        "resource_name": "ITSS_DEV",
                        "summary": "ITSS_DEV has no DLP policy assignment.",
                        "recommendation": "Assign a data policy.",
                    }
                ],
                "environments": [
                    {
                        "display_name": "ITSS_DEV",
                        "environment_sku": "Microsoft.BusinessAppPlatform/scopes/environments",
                        "is_default": False,
                        "region": "ukwest",
                        "runtime_state": "Enabled",
                        "dataverse_url": "https://org.crm.dynamics.com",
                        "solutions_collection_status": "complete",
                        "connection_references_collection_status": "complete",
                        "apps": [
                            {
                                "display_name": "Payroll",
                                "managed_status": "not_assessed",
                                "shared_users_count": 6,
                                "shared_groups_count": 0,
                            }
                        ],
                        "flows": [
                            {
                                "display_name": "Process Doc",
                                "state": "Published",
                                "managed_status": "not_assessed",
                            }
                        ],
                        "solutions": [
                            {
                                "unique_name": "Default",
                                "display_name": "Default Solution",
                                "managed_status": "unmanaged",
                            },
                            {
                                "unique_name": "DeltaHousing",
                                "display_name": "Delta Housing",
                                "version": "1.0.0.0",
                                "managed_status": "unmanaged",
                            },
                        ],
                        "connection_references": [
                            {
                                "display_name": "SQL Server",
                                "connector_id": "/providers/Microsoft.PowerApps/apis/shared_sql",
                                "state_code": 0,
                            }
                        ],
                    }
                ],
            }
        )
    }

    assert "Default" not in sections["Environments"].rows[0][1]
    assert sections["Environments"].rows[0][1] == "Unknown"
    assert "data policy" in sections["Environments"].recommendation
    assert "Delta Housing" in sections["Solutions"].recommendation
    assert "Default Solution" not in sections["Solutions"].recommendation
    assert "not in a solution" in sections["Power Apps"].recommendation.casefold() or (
        "does not yet record" in sections["Power Apps"].recommendation
    )
    assert "Process Doc" in sections["Power Automate"].rows[0][1]
    assert "SQL Server" in sections["Connectors and data policies"].recommendation
    assert "Recommendation" in sections["Findings"].headers
    assert "Assign a data policy." in sections["Findings"].rows[0][5]


def test_app_section_names_the_owner_and_share_recipients() -> None:
    sections = {
        section.title: section
        for section in build_sections(
            {
                "environments": [
                    {
                        "display_name": "Production",
                        "apps": [
                            {
                                "display_name": "Payroll",
                                "owner_name": "Ada Lovelace",
                                "owner_email": "ada@contoso.com",
                                "permissions_collection_status": "complete",
                                "permissions": [
                                    {
                                        "display_name": "Ada Lovelace",
                                        "email": "ada@contoso.com",
                                        "principal_type": "User",
                                        "role_name": "Owner",
                                    },
                                    {
                                        "display_name": "Finance",
                                        "principal_type": "Group",
                                        "role_name": "CanView",
                                    },
                                ],
                            }
                        ],
                    }
                ]
            }
        )
    }

    row = sections["Power Apps"].rows[0]
    assert row[2] == "Ada Lovelace (ada@contoso.com)"
    assert row[3] == "Finance, CanView"
    assert "Owner" in sections["Power Apps"].headers
    assert sections["App sharing"].rows[0][2] == "Finance"
    assert sections["App sharing"].rows[0][3] == "CanView"
