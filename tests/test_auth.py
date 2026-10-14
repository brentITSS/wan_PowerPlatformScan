from ppscanner import auth
from ppscanner.auth import (
    AccessTokens,
    AuthenticationError,
    Settings,
    acquire_access_tokens,
)


def test_access_tokens_use_admin_scope_for_tenant_inventory(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []

    class FakeApplication:
        def __init__(self, client_id, authority) -> None:
            assert client_id == "client-id"
            assert authority.endswith("tenant-id")

        def initiate_device_flow(self, scopes):
            calls.append(tuple(scopes))
            return {"user_code": "code", "message": "Sign in"}

        def acquire_token_by_device_flow(self, flow):
            return {"access_token": "power-platform-token"}

        def get_accounts(self):
            return [{"username": "admin@example.com"}]

        def acquire_token_silent(self, scopes, account):
            assert account["username"] == "admin@example.com"
            calls.append(tuple(scopes))
            return {"access_token": "power-apps-service-token"}

    monkeypatch.setattr(auth.msal, "PublicClientApplication", FakeApplication)
    tokens = acquire_access_tokens(Settings("tenant-id", "client-id"))

    assert tokens.power_platform == "power-platform-token"
    assert tokens.power_apps_service == "power-apps-service-token"
    assert tokens.power_automate == "power-apps-service-token"
    assert tokens.power_automate_error is None
    assert calls == [
        ("https://api.powerplatform.com/PowerApps.Apps.Read",),
        ("https://service.powerapps.com//.default",),
        ("https://api.powerplatform.com/PowerAutomate.Flows.Read",),
    ]


def test_access_tokens_request_dataverse_for_the_environment_host() -> None:
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    class FakeApplication:
        def acquire_token_silent(self, scopes, account):
            calls.append((tuple(scopes), account))
            return {"access_token": "dataverse-token"}

    account = {"username": "admin@example.com"}
    tokens = AccessTokens(
        "power-platform-token",
        "power-apps-service-token",
        FakeApplication(),
        account,
    )

    assert tokens.acquire_dataverse_token("https://org.crm.dynamics.com/") == (
        "dataverse-token"
    )
    assert calls == [(("https://org.crm.dynamics.com/user_impersonation",), account)]


def test_flow_consent_failure_keeps_the_other_tokens(monkeypatch) -> None:
    class FakeApplication:
        def __init__(self, client_id, authority) -> None:
            del client_id, authority

        def initiate_device_flow(self, scopes):
            if "PowerAutomate.Flows.Read" in scopes[0]:
                return {"error": "consent_required", "error_description": "Need consent"}
            return {"user_code": "code", "message": "Sign in"}

        def acquire_token_by_device_flow(self, flow):
            return {"access_token": "power-platform-token"}

        def get_accounts(self):
            return [{"username": "admin@example.com"}]

        def acquire_token_silent(self, scopes, account):
            del account
            if any("PowerAutomate.Flows.Read" in scope for scope in scopes):
                return None
            return {"access_token": "legacy-token"}

    monkeypatch.setattr(auth.msal, "PublicClientApplication", FakeApplication)
    tokens = acquire_access_tokens(Settings("tenant-id", "client-id"))

    assert tokens.power_platform == "power-platform-token"
    assert tokens.power_apps_service == "legacy-token"
    assert tokens.power_automate is None
    assert tokens.power_automate_error is not None
    assert "Need consent" in tokens.power_automate_error


def test_access_tokens_reject_untrusted_dataverse_urls() -> None:
    tokens = AccessTokens(
        "power-platform-token",
        "power-apps-service-token",
        None,
        None,
    )

    try:
        tokens.acquire_dataverse_token("https://attacker.example/")
    except AuthenticationError as error:
        assert "invalid Dataverse instance URL" in str(error)
    else:
        raise AssertionError("An untrusted Dataverse URL must be rejected.")
