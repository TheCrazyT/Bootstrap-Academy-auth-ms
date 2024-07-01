"""Endpoints for webauthn"""

# Some notes:
#  * for local testing, only use "localhost" instead of "127.0.0.1"
#    , since ip-addresses do not seem to be supported by webauthn
#  * also make shure that FRONTEND_BASE_URL is "http://localhost:3000"

import secrets
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticationCredential,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    RegistrationCredential,
    UserVerificationRequirement,
)

from ..settings import settings
from ..utils.docs import responses


router = APIRouter()

RP_NAME = "BootstrapAcademy"

# TODO:
# That "challenge" would somehow need to be stored (but without login we have no sesssion, yet) ...
# The following arrays need to be in session/database:
LAST_CHALLENGES: list[bytes] = []
LAST_REG_INFOS: list[dict[str, Any]] = []


def get_server_name() -> str:
    result = urlparse(settings.frontend_base_url).hostname
    if result is None:
        raise Exception("frontend_base_url was None")
    return result


@router.get("/generate-authentication-options", responses=responses(PublicKeyCredentialRequestOptions))
async def generate_authentication_options_request() -> Any:
    """
    Return the current webauthn options.

    *Requirements:*
    """
    server_name = get_server_name()
    # TODO: "LAST_CHALLENGES" is for testing only, store in session (db?) later
    challenge = secrets.token_bytes(16)
    LAST_CHALLENGES.append(challenge)

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=dev["credentialID"], transports=dev["transports"]) for dev in LAST_REG_INFOS
    ]

    return generate_authentication_options(
        rp_id=server_name,
        challenge=challenge,
        timeout=12000,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )


@router.get("/generate-registration-options", responses=responses(PublicKeyCredentialCreationOptions))
async def generate_registration_options_request() -> Any:
    """
    Return the current webauthn options.

    *Requirements:*
    """
    server_name = get_server_name()

    # TODO: "LAST_CHALLENGES" is for testing only, store in session (db?) later
    #       somehow get userid and username
    challenge = secrets.token_bytes(16)
    user_id = "test"  # use from param
    user_name = "test"  # use from param

    LAST_CHALLENGES.append(challenge)

    return generate_registration_options(
        rp_id=server_name, rp_name=RP_NAME, user_id=user_id, user_name=user_name, challenge=challenge, timeout=12000
    )


@router.post("/verify-authentication")
async def verify_authentication_request(credential: AuthenticationCredential) -> Any:
    """
    Verify login through webauthn

    *Requirements:*
    """
    server_name = get_server_name()

    # TODO: "LAST_CHALLENGES" is for testing only, get from session (db?) later
    challenge = LAST_CHALLENGES.pop()

    credential.raw_id = base64url_to_bytes(credential.id)
    credential.response.client_data_json = base64url_to_bytes(credential.response.client_data_json.decode("utf-8"))
    credential.response.authenticator_data = base64url_to_bytes(credential.response.authenticator_data.decode("utf-8"))
    credential.response.signature = base64url_to_bytes(credential.response.signature.decode("utf-8"))

    credential_public_key = None
    for reg_info in LAST_REG_INFOS:
        if reg_info["credentialID"] == credential.raw_id:
            credential_public_key = reg_info["credentialPublicKey"]
    if credential_public_key is None:
        return {"userVerified": False}
    print(credential)
    print(credential_public_key)
    return verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=server_name,
        expected_origin=settings.frontend_base_url,
        credential_public_key=credential_public_key,
        credential_current_sign_count=0,
        require_user_verification=True,
    )


@router.post("/verify-registration")
async def verify_registration_request(credential: RegistrationCredential) -> Any:
    """
    Verify registration through webauthn

    *Requirements:*
    """
    server_name = get_server_name()
    credential.raw_id = base64url_to_bytes(credential.id)
    credential.response.client_data_json = base64url_to_bytes(credential.response.client_data_json.decode("utf-8"))
    credential.response.attestation_object = base64url_to_bytes(credential.response.attestation_object.decode("utf-8"))

    # TODO: "LAST_CHALLENGES" is for testing only, get from session (db?) later
    challenge = LAST_CHALLENGES.pop()

    verify_resp = verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=server_name,
        expected_origin=settings.frontend_base_url,
        require_user_verification=True,
    )

    LAST_REG_INFOS.append(
        {
            "transports": credential.response.transports,
            "credentialPublicKey": verify_resp.credential_public_key,
            "credentialID": verify_resp.credential_id,
        }
    )
    return verify_resp
