"""Endpoints for webauthn"""

# Some notes:
#  * for local testing, only use "localhost" instead of "127.0.0.1", since ip-addresses do not seem to be supported by webauthn
#  * also make shure that FRONTEND_BASE_URL is "http://localhost:3000"

from base64 import urlsafe_b64decode
from typing import Any

import secrets

from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers import (base64url_to_bytes, bytes_to_base64url)
from webauthn.helpers.structs import (
    PYDANTIC_V2,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorTransport,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialCreationOptions,
    RegistrationCredential,
    AuthenticationCredential
)

from fastapi import APIRouter, Body, Request

from ..utils.docs import responses

from ..settings import settings

from urllib.parse import urlparse

router = APIRouter()

CREDENTIAL_ID = b"BootstrapAcademy"
RP_NAME = "BootstrapAcademy"

#TODO:
# Currently I'm just using example code from: https://github.com/duo-labs/py_webauthn/tree/494373e539050b96130c28477289feec65e5e19f/examples
# But those are only example-values!
# This means that "challenge" etc. will probably need to be generated ...
# That "challenge" would somehow need to be stored (but without login we have no sesssion, yet) ...
# At the moment, there seems to a problem with registering a key (although you get a "success" message)
# Not shure if SimpleWebAuthn is compatible with py_webauthn ...

@router.get("/generate-authentication-options", responses=responses(PublicKeyCredentialRequestOptions))
async def generate_authentication_options_request() -> Any:
    """
    Return the current webauthn options.

    *Requirements:* 
    """
    serverName = urlparse(settings.frontend_base_url).hostname
    #TODO get generated challenge
    challenge = b"1234567890"

    return generate_authentication_options(
        rp_id = serverName,
        challenge = challenge,
        timeout = 12000,
        allow_credentials = [PublicKeyCredentialDescriptor(id=CREDENTIAL_ID, transports=[AuthenticatorTransport.INTERNAL,AuthenticatorTransport.USB,AuthenticatorTransport.NFC,AuthenticatorTransport.BLE,AuthenticatorTransport.CABLE,AuthenticatorTransport.HYBRID])],
        user_verification = UserVerificationRequirement.REQUIRED
    );

@router.get("/generate-registration-options", responses=responses(PublicKeyCredentialCreationOptions))
async def generate_registration_options_request() -> Any:
    """
    Return the current webauthn options.

    *Requirements:* 
    """
    serverName = urlparse(settings.frontend_base_url).hostname
    # TODO: for testing only use secrets.token_bytes(16) later
    #       value also needs to be stored somwhere
    challenge = b"1234567890" 
    user_id = "test" #use from param
    user_name = "test" #use from param

    return generate_registration_options(
        rp_id = serverName,
        rp_name = RP_NAME,
        user_id = user_id,
        user_name = user_name,
        challenge = challenge,
        timeout = 12000
    );

@router.post("/verify-authentication")
async def verify_authentication_request(credential: AuthenticationCredential, some_other_arg: str) -> Any:
    """
    Verify login through webauthn

    *Requirements:* 
    """
    serverName = urlparse(settings.frontend_base_url).hostname
    #TODO get generated challenge
    challenge = b"1234567890"
    return verify_authentication_response(
        # Demonstrating the ability to handle a stringified JSON version of the WebAuthn response
        credential = credential,
        expected_challenge=challenge,
        expected_rp_id=serverName,
        expected_origin=settings.frontend_base_url,
        credential_public_key=base64url_to_bytes(
            "pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE"
        ),
        credential_current_sign_count=0,
        require_user_verification=True,
    )

@router.post("/verify-registration")
async def verify_registration_request(credential: RegistrationCredential) -> Any:
    """
    Verify registration through webauthn

    *Requirements:* 
    """
    serverName = urlparse(settings.frontend_base_url).hostname
    credential.raw_id = base64url_to_bytes(credential.id)
    credential.response.client_data_json = base64url_to_bytes(credential.response.client_data_json.decode("utf-8"))
    credential.response.attestation_object = base64url_to_bytes(credential.response.attestation_object.decode("utf-8"))
    #TODO get generated challenge
    challenge = b"1234567890"
    return verify_registration_response(
        # Demonstrating the ability to handle a stringified JSON version of the WebAuthn response
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=serverName,
        expected_origin=settings.frontend_base_url,
        require_user_verification=True,
    )