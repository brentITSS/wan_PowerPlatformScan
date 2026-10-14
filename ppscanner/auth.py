import os
from dataclasses import dataclass
from urllib.parse import urlparse

import msal
from dotenv import load_dotenv


class AuthenticationError(RuntimeError):
    pass


@dataclass(frozen=True)
class AccessTokens:
    power_platform: str
    power_apps_service: str
    _application: msal.PublicClientApplication
    _account: dict[str, str] | None
    power_automate: str | None = None
    power_automate_error: str | None = None

    def acquire_dataverse_token(self, instance_url: str) -> str:
        try:
            parsed = urlparse(instance_url)
            port = parsed.port
        except ValueError as error:
            raise AuthenticationError(
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
            raise AuthenticationError(
                "The environment returned an invalid Dataverse instance URL."
            )
        scopes = [f"{parsed.scheme}://{parsed.netloc}/user_impersonation"]
        result = (
            self._application.acquire_token_silent(scopes, account=self._account)
            if self._account is not None
            else None
        )
        token = result.get("access_token") if isinstance(result, dict) else None
        if token:
            return token
        return _acquire_device_code_token(
            self._application,
            scopes,
            "Dataverse app managed-status inventory",
        )


@dataclass(frozen=True)
class Settings:
    tenant_id: str
    client_id: str

    @classmethod
    def from_environment(cls) -> "Settings":
        load_dotenv()
        tenant_id = os.getenv("PP_TENANT_ID", "").strip()
        client_id = os.getenv("PP_CLIENT_ID", "").strip()
        missing = [
            name
            for name, value in (
                ("PP_TENANT_ID", tenant_id),
                ("PP_CLIENT_ID", client_id),
            )
            if not value
        ]
        if missing:
            names = ", ".join(missing)
            raise AuthenticationError(
                f"Missing {names}. Copy .env.example to .env and set these values."
            )
        return cls(tenant_id=tenant_id, client_id=client_id)


def acquire_access_tokens(settings: Settings) -> AccessTokens:
    authority = f"https://login.microsoftonline.com/{settings.tenant_id}"
    application = msal.PublicClientApplication(
        client_id=settings.client_id,
        authority=authority,
    )
    power_platform_scopes = [
        "https://api.powerplatform.com/PowerApps.Apps.Read",
    ]
    power_platform_token = _acquire_device_code_token(
        application,
        power_platform_scopes,
        "Power Platform API",
    )

    legacy_scope = ["https://service.powerapps.com//.default"]
    accounts = application.get_accounts()
    legacy_result = (
        application.acquire_token_silent(legacy_scope, account=accounts[0])
        if accounts
        else None
    )
    legacy_token = (
        legacy_result.get("access_token") if isinstance(legacy_result, dict) else None
    )
    if not legacy_token:
        legacy_token = _acquire_device_code_token(
            application,
            legacy_scope,
            "Power Apps Service admin API",
        )
    accounts = application.get_accounts()
    account = accounts[0] if accounts else None
    power_automate_token: str | None = None
    power_automate_error: str | None = None
    try:
        power_automate_token = _acquire_silent_or_device_token(
            application,
            ["https://api.powerplatform.com/PowerAutomate.Flows.Read"],
            "Power Automate flow inventory",
            account,
        )
    except AuthenticationError as error:
        power_automate_error = str(error)
    return AccessTokens(
        power_platform=power_platform_token,
        power_apps_service=legacy_token,
        _application=application,
        _account=account,
        power_automate=power_automate_token,
        power_automate_error=power_automate_error,
    )


def _acquire_silent_or_device_token(
    application: msal.PublicClientApplication,
    scopes: list[str],
    resource_name: str,
    account: dict[str, str] | None,
) -> str:
    result = (
        application.acquire_token_silent(scopes, account=account)
        if account is not None
        else None
    )
    token = result.get("access_token") if isinstance(result, dict) else None
    if token:
        return token
    return _acquire_device_code_token(application, scopes, resource_name)


def _acquire_device_code_token(
    application: msal.PublicClientApplication,
    scopes: list[str],
    resource_name: str,
) -> str:
    flow = application.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        raise AuthenticationError(
            f"Could not start Microsoft sign-in for {resource_name}: "
            f"{flow.get('error_description', flow.get('error', 'unknown error'))}"
        )

    print(flow["message"])
    result = application.acquire_token_by_device_flow(flow)
    access_token = result.get("access_token")
    if not access_token:
        error = result.get("error", "authentication_failed")
        description = result.get("error_description", "No access token was returned.")
        raise AuthenticationError(
            f"Microsoft sign-in for {resource_name} failed ({error}): {description}"
        )
    return access_token
