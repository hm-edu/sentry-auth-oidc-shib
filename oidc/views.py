from __future__ import annotations

import logging
import time
import requests
from django.http import HttpRequest
from rest_framework.response import Response

from sentry.auth.services.auth.model import RpcAuthProvider
from sentry.auth.view import AuthView
from sentry.organizations.services.organization.model import RpcOrganization
from sentry.plugins.base.response import DeferredResponse
from .constants import ERR_INVALID_RESPONSE, ISSUER
from .constants import (USERINFO_ENDPOINT)

logger = logging.getLogger("sentry.auth.oidc")


class FetchUser(AuthView):
    def __init__(self, domains, version, *args, **kwargs):
        self.domains = domains
        self.version = version
        super().__init__(*args, **kwargs)

    def get_user_info(self, bearer_token):
        endpoint = USERINFO_ENDPOINT
        bearer_auth = "Bearer " + bearer_token
        retry_codes = [429, 500, 502, 503, 504]
        for retry in range(10):
            if 10 < retry:
                return {}
            r = requests.get(
                endpoint + "?schema=openid",
                headers={"Authorization": bearer_auth},
                timeout=2.0,
            )
            if r.status_code in retry_codes:
                wait_time = 2**retry * 0.1
                time.sleep(wait_time)
                continue
            return r.json()

    def dispatch(self, request: HttpRequest, **kwargs) -> Response: # type: ignore
        if "pipeline" in kwargs:
            helper = kwargs["pipeline"]
        elif "helper" in kwargs:
            helper = kwargs["helper"]
        else:
            raise TypeError(
                f"FetchUser.dispatch() is missing either the `pipeline` or the `helper` keyword argument."
            )
        data = helper.fetch_state("data")

        try:
            access_token = data["access_token"]
        except KeyError:
            logger.error("Missing access_token in OAuth response: %s" % data)
            return helper.error(ERR_INVALID_RESPONSE)

        payload = self.get_user_info(access_token)

        # support legacy style domains with pure domain regexp
        if self.version is None:
            domain = extract_domain(payload["email"])
        else:
            domain = payload.get("hd")

        helper.bind_state("domain", domain)
        helper.bind_state("user", payload)

        return helper.next_step()


def oidc_configure_view(
    request: HttpRequest, organization: RpcOrganization, auth_provider: RpcAuthProvider
) -> DeferredResponse:
    config = auth_provider.config
    if config.get("domain"):
        domains: list[str] | None
        domains = [config["domain"]]
    else:
        domains = config.get("domains")
    return DeferredResponse(
        "oidc/configure.html",
        {"provider_name": ISSUER or "", "domains": domains or []}
    )


def extract_domain(email):
    return email.rsplit("@", 1)[-1]
