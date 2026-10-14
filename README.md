# Power Platform Tenant Scanner

The current milestone is a read-only scanner that signs in interactively,
inventories tenant-admin environments, Power Apps, cloud flows, solutions, and
connection references, reads DLP policy assignment, stores a timestamped JSON
snapshot with evidence-backed findings, and can export or open that snapshot
locally.

## Prerequisites

- Windows with Python 3.13 installed (or another supported Python 3 version).
- Dependencies installed in the project `.venv`.
- A single-tenant Microsoft Entra app registration with the delegated
  Power Apps Service `User` scope, Power Platform API `PowerApps.Apps.Read`
  and `PowerAutomate.Flows.Read` scopes, plus Dynamics CRM
  `user_impersonation`, with consent.
- A signed-in user with the directly assigned Power Platform Administrator,
  Dynamics 365 Administrator, or Global Administrator role for tenant-wide
  environment discovery, and Dataverse privileges to read Canvas App,
  Model-driven App, Solution, and Connection Reference records in the
  environments being scanned.

The scanner uses Microsoft's tenant-admin **List environments** endpoint
(`api.bap.microsoft.com`, version `2020-10-01`) for environment discovery. The
endpoint is documented as preview. It requires an appropriately assigned
tenant admin role; without that role the scan fails rather than silently
falling back to a user-scoped list.

## Configure sign-in

1. A single-tenant public-client app registration named **Power Platform Tenant Scanner** is provisioned for this project.
2. It requests delegated **User** on **Power Apps Service** for tenant
   environment discovery and DLP policies, **PowerApps.Apps.Read** and
   **PowerAutomate.Flows.Read** on the **Power Platform API** for app and
   cloud-flow inventory, and **user_impersonation** on **Dynamics CRM** for
   Dataverse app, solution, and connection-reference metadata. An
   administrator must grant consent for these permissions. If flow consent is
   missing, the rest of the scan still runs and records flow inventory as
   `permission_denied`.
3. The local `.env` is configured with this tenant and app registration. For
   another checkout, copy `.env.example` to `.env` and set `PP_TENANT_ID` and
   `PP_CLIENT_ID`.
4. Sign-in uses MSAL device code flow. The scanner may request tokens for the
   Power Apps Service admin endpoint, Power Automate flow inventory, and each
   Dataverse environment. It first attempts silent token acquisition after
   your initial sign-in. You choose the user account when Microsoft prompts
   you. The scanner does not ask for or store your password, client secret,
   or access token.

### Which values to change

| Setting | What it selects | When to change it |
|---|---|---|
| `PP_TENANT_ID` | The Microsoft Entra tenant the scanner requests sign-in against. | Change when scanning a different tenant. |
| `PP_CLIENT_ID` | The Entra app registration the scanner uses. | Change when using an app registration created in another tenant, or a separately approved app. |

The user account is selected during interactive sign-in; it is not a `.env` password or credential. Signing in as another user in the configured tenant may be enough if that user has the necessary Power Platform access. This app registration is single-tenant, so changing only `PP_TENANT_ID` does **not** make it usable in a different tenant: that tenant needs its own app registration, delegated permission, and consent, or the app must be deliberately changed to support multiple tenants and consented there.

For local use, put these settings in the git-ignored `.env` file. A future hosted web app should receive the same setting names through its application configuration/environment variables; do not copy a local `.env` file or user passwords into the web host. The current delegated device-code flow is intended for an interactive user, not unattended background scanning.

Microsoft references:

- [Power Platform API authentication (legacy)](https://learn.microsoft.com/power-platform/admin/programmability-authentication)
- [List environments (preview)](https://learn.microsoft.com/power-platform/admin/list-environments)
- [Power Platform service admin roles](https://learn.microsoft.com/power-platform/admin/use-service-admin-role-manage-tenant)
- [Get AdminApps (preview)](https://learn.microsoft.com/rest/api/power-platform/powerapps/apps/get-admin-apps)
- [CanvasApp table reference](https://learn.microsoft.com/power-apps/developer/data-platform/webapi/reference/canvasapp?view=dataverse-latest)
- [Model-driven App (AppModule) table reference](https://learn.microsoft.com/power-apps/developer/data-platform/webapi/reference/appmodule?view=dataverse-latest)
- [List Cloud Flows](https://learn.microsoft.com/rest/api/power-platform/powerautomate/cloud-flows/list-cloud-flows)
- [Solution table reference](https://learn.microsoft.com/power-apps/developer/data-platform/webapi/reference/solution?view=dataverse-latest)
- [Data loss prevention policies](https://learn.microsoft.com/power-platform/admin/wp-data-loss-prevention)

## Run a scan

From the project root, activate the project environment and run:

```powershell
.\.venv\Scripts\Activate.ps1
python -m ppscanner scan
```

By default, the JSON snapshot is saved under `.data/snapshots/`, which is excluded from source control. To use a different directory:

```powershell
python -m ppscanner scan --output-dir .data\my-snapshots
```

Each environment includes separate app inventory and managed-status coverage.
App rows include the API's app identifier/name, type, display name, timestamps,
owner, the people and groups the app is shared with, and managed status.
Managed status is read from the Dataverse `canvasapp.ismanaged` or
`appmodule.ismanaged` field;
`managed_status` is `managed` or `unmanaged` only when the corresponding
Dataverse app record is found. Unsupported app types, missing Dataverse
instances, unavailable permissions, and unmatched app IDs remain
`not_assessed` with coverage status and an explanation. This does not establish
an app's enabled/disabled state.

The snapshot contains normalized environment and app metadata and scan
provenance; it does not store access tokens or the full raw API response. An
app collection failure for one environment is recorded as `permission_denied`
or `failed` without presenting that environment as an empty successful result.
Managed-status collection is also recorded independently as `complete`,
`partial`, `unsupported`, `permission_denied`, or `failed`.

Every snapshot identifies environment collection as `tenant_admin` scope. A
successful response is the tenant-admin API's list for this tenant; it is not
a substitute for validating the count against the Power Platform admin
center, particularly because the endpoint is preview.

Cloud flows come from List Cloud Flows. That operation does not publish
`ismanaged`, so a flow's managed status is taken from the Dataverse solutions
that contain it. An app or flow that is only in the default solution is
reported as outside a custom solution. Solutions use Dataverse
`solution.ismanaged`. Connection references store the connector identifier and
display name only. DLP policies come from the Power Platform for Admins V2
policy list, including environment scope and connector classifications when
the policy detail returns them. Environment creator names are not stored.
App and flow owner names, and the names of people or groups an app is shared
with, are stored with their email address when the admin permission list or
Dataverse user record returns one. A new scan is required before an older
snapshot can show those names.

Findings are evaluated while the scan is saved. They record the rule, severity,
confidence, evidence, and a recommendation. A count of shared users is not
treated as proof of external sharing. An environment type of Developer or
Trial is informational and is not by itself a defect. A missing resource in a
partial collection is not treated as a deletion when two snapshots are compared.

`environments` and the HTML report group the snapshot into environments, apps,
sharing, flows, custom unmanaged solutions, connectors, and findings. Each
section ends with a recommendation based on what that snapshot actually
contains. The findings table also keeps a recommendation column. Opening a
saved snapshot applies the current finding rules to the inventory already
stored there. Environment makers, Managed Environments, and connection owners
appear after the next scan.

Review a saved snapshot, export it, or open the local dashboard:

```powershell
python -m ppscanner environments
python -m ppscanner findings
python -m ppscanner report --format html
python -m ppscanner compare .data\snapshots\older.json .data\snapshots\newer.json
python -m ppscanner serve
```

`serve` listens only on `127.0.0.1` and reads the JSON snapshots already on
this computer. The dashboard is at `http://127.0.0.1:8000`.

## Run tests

```powershell
python -m pytest
```
