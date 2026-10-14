# Power Platform Tenant Scanner — Initial Project Scope

**Status:** Initial proposal  
**Version:** 0.1  
**Date:** 12 October 2026

## 1. Product summary

Build a read-only assessment application that inventories a Microsoft Power Platform tenant, captures a timestamped view of its environments and assets, identifies governance and security risks, and gives actionable, evidence-based recommendations. The same scanning engine must be usable from a terminal script and through a browser-based dashboard.

The scanner is an assessment and reporting tool, not a replacement for the Power Platform admin center, Microsoft Purview, or the Center of Excellence (CoE) Starter Kit. It should make its coverage and limitations visible rather than imply it can see data unavailable to its identity or the APIs it uses.

## 2. Goals

- Make tenant-wide inventory and governance posture understandable in one place.
- Capture repeatable, point-in-time snapshots that can be exported and compared.
- Highlight risks with evidence, severity, confidence, affected resources, and remediation guidance.
- Support both unattended/scripted terminal runs and interactive browser-based exploration.
- Use least privilege, protect collected tenant data, and default to read-only operation.
- Make collection coverage, authorization gaps, API failures, and stale or incomplete data explicit.

## 3. Intended users

- Power Platform and tenant administrators responsible for inventory and governance.
- Security, compliance, and risk teams reviewing exposure and control effectiveness.
- Environment owners and makers reviewing issues affecting their environments or apps.
- Auditors who need a dated, exportable record of what was assessed and what was visible.

## 4. Initial product boundaries

### In scope

- Discover environments across the tenant and report their properties and lifecycle state.
- Inventory supported Power Apps, Power Automate cloud flows, solutions, connectors, and relevant environment settings.
- Distinguish managed and unmanaged solutions/components when the source data exposes that distinction. Do not infer that an individual app is managed solely from its environment or solution association.
- Assess selected governance signals, such as environment type and ownership, DLP policy coverage/configuration, sharing and role exposure, unmanaged assets, orphaned ownership, and relevant tenant/environment settings.
- Produce explainable findings and practical recommendations mapped to official Microsoft guidance where possible.
- Record snapshot metadata, provenance, coverage, and collection errors; export reports for sharing and analysis.
- Offer a CLI and a browser dashboard over the same domain and scanning services.

### Out of scope for the first release

- Automatically changing tenant, environment, policy, app, flow, or user configuration.
- Guaranteeing discovery of every workload, setting, audit event, or dependency regardless of API and permissions.
- Replacing Purview, Microsoft Defender, admin-center controls, licensing/billing systems, or the CoE Starter Kit.
- Runtime testing, source-code security analysis, or validation of an app's business logic.
- Multi-tenant SaaS hosting, delegated customer onboarding, and high-availability enterprise deployment until separately designed.
- Treating a finding as a compliance certification or a definitive statement that a resource is safe or unsafe.

## 5. Core user experience

### CLI

The CLI should provide commands along these lines:

- `scan` — authenticate, collect the selected tenant scope, evaluate checks, and save a snapshot.
- `environments` — list discovered environments and their key attributes.
- `findings` — filter findings by severity, category, environment, or resource.
- `report` — export a selected snapshot as JSON, CSV, or HTML.
- `compare` — summarize changes between two snapshots.
- `auth` / `status` — establish or inspect authentication and effective collection coverage.

Exact command names and options will be finalized during implementation. Long-running scans should show progress, support cancellation, and return a non-zero exit status for failed or materially incomplete scans.

### Web dashboard

- Summary of the latest scan, tenant/environment coverage, findings by severity, and scan health.
- Searchable and filterable environment and asset inventory.
- Environment detail pages showing properties, assets, findings, and available governance evidence.
- Finding detail pages explaining the evidence, impact, confidence, affected resources, and mitigation.
- Snapshot history and comparisons, with download/export controls.
- Clear warnings when data is incomplete, stale, permission-limited, or unavailable.

The initial deployment target is a locally run web application. Remote or multi-user hosting requires a separate security and operational design, including user authorization, session protection, secret management, and data-retention controls.

## 6. Initial inventory and assessment areas

The scanner should use a capability-based collector design. Each area must declare the source/API, required permission, collection result, and limitations.

| Area | Initial information and example assessment signals |
|---|---|
| Tenant and scan context | Tenant identity, scan start/end time in UTC, scanner version, selected scope, collector/API versions, and authenticated identity context. Avoid storing tokens. |
| Environments | Environment ID/name, type, region, lifecycle/state, creation metadata when available, and inventory coverage. Flag unexpected personal/developer or unmanaged environment sprawl according to configurable policy, not as an unconditional defect. |
| Apps and solutions | Supported app types, ownership, sharing/role information where available, solution association, managed/unmanaged status where authoritative, and last-modified metadata. Flag broad sharing, orphaned owners, and unmanaged production components when evidence supports it. The preview Power Platform API Get AdminApps operation supplies app inventory; managed status is independently read from the authoritative Dataverse `canvasapp.ismanaged` or `appmodule.ismanaged` property when the app record can be matched. Other app types, unavailable Dataverse access, and unmatched records remain explicitly unassessed. |
| Power Automate | Supported cloud-flow inventory, state, owners, sharing, solution association, and connector references where available. Flag orphaned ownership, unmanaged production flows, and risky sharing patterns. |
| Connectors and connections | Connector types/references and available classification metadata. Flag use of connectors prohibited or restricted by applicable DLP policy; do not collect connection secrets or payloads. |
| Data policies (DLP) | Policy inventory, scope/assignment, connector classifications, and detectable gaps or conflicts. Describe only what the collected policy data proves; do not claim to observe runtime enforcement unless a source provides that evidence. |
| Environment governance | Available environment settings, security groups, roles, maker controls, capacity/lifecycle indicators, and policy assignment evidence. Identify missing controls only when their absence can be established. |
| Ownership and access | Available owners, users, groups, roles, and sharing assignments. Detect orphaned or unusually broad access where data and defined rules permit. Minimize personal data in reports. |
| Audit and operations (later phase) | Optional audit/activity signals, retention/availability constraints, freshness, and licensing/permission requirements. Keep separate from baseline inventory until feasibility is verified. |

The first release should prioritize reliable environment discovery, app/flow inventory, supported managed/unmanaged status, DLP/governance signals, risk findings, and exports. Each collector must be independently testable and may report `complete`, `partial`, `unsupported`, `permission_denied`, or `failed` rather than fabricate empty results. The app collector records inventory coverage independently from managed-status coverage; managed status is populated only from the Dataverse app record's `ismanaged` property.

## 7. Risk and recommendation model

Every finding should include:

- Stable rule ID and rule/check version.
- Category, severity (`critical`, `high`, `medium`, `low`, or `informational`), and confidence.
- Tenant/environment/resource identifiers and human-readable names when available.
- Evidence and source, collection timestamp, and any assumptions or coverage limitations.
- Why it matters, recommended next steps, and a link to authoritative guidance where available.
- Whether the finding is confirmed, potential, or not assessable due to missing evidence.

Severity and confidence are separate. A configurable policy profile should determine thresholds and exceptions; a single baseline must not silently treat every tenant's business context as identical. Recommendations are advisory and must not execute remediation.

Initial rule candidates include broad external or tenant-wide sharing, orphaned ownership, production assets outside managed solutions, use of connectors inconsistent with DLP policy, environments without expected governance, and high-risk settings detectable from available configuration. Validate each rule against authoritative Microsoft data definitions before implementation.

## 8. Snapshot, comparison, and reporting

- A snapshot is an immutable record of what a particular scan observed; rescans create new snapshots.
- Store scan ID, tenant ID, timestamps, scanner/rule versions, scope, per-collector status, counts, and errors.
- Preserve source identifiers and timestamps so users can distinguish current observations from older or derived information.
- Compare snapshots by stable resource identifiers and report added, removed, changed, and newly/previously detected findings.
- A missing item in a partial scan must not be presented as a confirmed deletion.
- Initial export formats: JSON for machine processing; CSV for tabular review; HTML for a shareable human-readable report.
- Clearly mark sensitive exports and avoid including credentials, access tokens, connection secrets, or flow/app data payloads.

## 9. Non-functional requirements

- **Security:** read-only collection by default; least-privileged authorization; no secrets in source control or logs; secure session handling; explicit protection for local snapshot storage and exports.
- **Reliability:** pagination, bounded retries/backoff for transient failures and throttling, timeouts, resumable or safely repeatable collectors, and per-collector error reporting.
- **Transparency:** show scan coverage, source freshness, permission gaps, skipped resources, unsupported data, and partial results in CLI, UI, and exports.
- **Performance:** stream progress for long scans; avoid loading an entire large tenant into memory unnecessarily; support scoped scans and configurable concurrency that respects service limits.
- **Accessibility:** keyboard-friendly navigation, readable contrast, meaningful labels, and non-color-only severity indicators.
- **Maintainability:** shared collection/evaluation/domain layers; isolated API clients; versioned checks; automated tests for collectors, rules, exports, auth boundaries, and snapshot comparisons.
- **Portability:** supported Python runtime and documented local setup; configuration through environment variables or a local ignored settings file.

## 10. Proposed initial technical baseline

- **Language/runtime:** Python 3.12 or newer supported Python 3 release.
- **Architecture:** one Python package with a shared scanning/domain core; Typer CLI; FastAPI web server and server-rendered dashboard. The CLI and UI call the same application services.
- **Identity:** Microsoft Entra ID authentication through MSAL. Use interactive delegated sign-in for local use; evaluate app-only/certificate authentication separately for scheduled automation based on the support and permissions of each Power Platform API. Never assume one token audience or one permission set covers every collector.
- **Collection:** documented Microsoft Power Platform admin/management interfaces and Microsoft Graph only where appropriate. Confirm API support, endpoint version, licensing, role requirements, throttling, and tenant/cloud availability per collector.
- **Local persistence:** SQLite for initial single-user snapshots and metadata; keep snapshot access restricted to the local user. Design an abstraction before adding a shared database.
- **Web:** FastAPI with server-rendered templates, local-only bind by default, and explicit authentication/session protection before exposing beyond localhost.
- **Exports:** built-in JSON/CSV generation and HTML report rendering.
- **Configuration:** environment variables; secrets excluded from source control. Store no access tokens in scan snapshots.

The technical baseline is a starting point, not a commitment to an unverified Power Platform endpoint or permission model. Verify current Microsoft documentation and tenant-specific access before implementing each collector.

For the initial environment-inventory prototype, use Microsoft's tenant-admin **List environments** endpoint (`api.bap.microsoft.com`, API version `2020-10-01`) with the legacy Power Apps Service delegated `User` permission. Microsoft currently labels this endpoint preview. Require an appropriately assigned Power Platform Administrator, Dynamics 365 Administrator, or Global Administrator role; record tenant-admin scope and preview status in each snapshot, fail visibly when admin access is denied, and do not silently fall back to a user-scoped environment list. Validate endpoint coverage against the admin center before relying on results for governance decisions. App inventory continues to use the Power Platform API and its separate `PowerApps.Apps.Read` permission.

## 11. Acceptance criteria for an initial usable release

1. A user can authenticate without placing a password or access token in a command argument, source file, or log.
2. A tenant-wide scan discovers environments visible to the authenticated identity and reports visibility/permission limitations.
3. Supported app, flow, solution, and governance inventory includes explicit collection status and source provenance.
4. Managed/unmanaged classification is shown only when based on authoritative source data; unknown is a valid result.
5. Findings provide evidence, severity, confidence, affected resources, and actionable mitigation; every rule can be tested with representative inputs.
6. A completed scan is persisted as a timestamped snapshot; partial scans are labeled and cannot produce misleading deletion/change claims.
7. CLI and browser dashboard show the same snapshot and finding information.
8. JSON, CSV, and HTML exports identify scan time, scope, coverage, and limitations.
9. No scan operation changes Power Platform tenant state.
10. Unit and integration tests cover pagination, throttling/failures, permission gaps, rule evaluation, snapshot comparison, exports, and unauthorized web access.

## 12. Delivery phases

1. **Discovery and API validation:** verify official interfaces, permissions, licensing, tenant/cloud compatibility, and representative sample responses for each target inventory area. For environment discovery, explicitly validate preview API behavior, result coverage, and required admin role assignment.
2. **Foundation:** package structure, configuration, MSAL auth, collector contracts, structured logging, test harness, and SQLite snapshot model.
3. **MVP collectors:** environments, supported apps/flows/solutions, DLP/governance signals, and transparent coverage reporting.
4. **Rules and reports:** versioned baseline rules, evidence-backed recommendations, JSON/CSV/HTML exports, and snapshot comparison.
5. **CLI and web UI:** shared services, terminal workflows, local dashboard, search/filtering, detail views, and authentication/session checks.
6. **Hardening and expansion:** tenant-scale performance, scheduled automation, richer audit signals, additional asset types, and a separately reviewed multi-user deployment model.

## 13. Decisions to confirm before production use

- Which Power Platform clouds and tenant types must be supported?
- Which identity model is approved for interactive and scheduled scans, and which administrative roles/permissions can be granted?
- What data-retention, encryption, export, and access policies apply to stored snapshots?
- Should risk profiles be Microsoft baseline, organization-specific, or both?
- What scale (environment/resource counts), scan frequency, and maximum scan duration are expected?
- Is the first web experience strictly local, or must it be hosted for multiple users?
- Which audit-history, licensing, capacity, and premium-connector insights are essential for the first production milestone?
