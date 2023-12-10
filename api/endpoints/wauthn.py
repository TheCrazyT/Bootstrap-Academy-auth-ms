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

RP_NAME = "BootstrapAcademy"

#TODO:
# That "challenge" would somehow need to be stored (but without login we have no sesssion, yet) ...
# The following arrays need to be in session/database:
LAST_CHALLENGES = []
LAST_REG_INFOS = []


@router.get("/generate-authentication-options", responses=responses(PublicKeyCredentialRequestOptions))
async def generate_authentication_options_request() -> Any:
    """
    Return the current webauthn options.

    *Requirements:* 
    """
    server_name = urlparse(settings.frontend_base_url).hostname
    # TODO: "LAST_CHALLENGES" is for testing only, store in session (db?) later
    challenge = secrets.token_bytes(16)
    LAST_CHALLENGES.append(challenge)

    allow_credentials = [PublicKeyCredentialDescriptor(
            id=dev["credentialID"],
            transports=dev["transports"]
        ) for dev in LAST_REG_INFOS
    ]

    return generate_authentication_options(
        rp_id = server_name,
        challenge = challenge,
        timeout = 12000,
        allow_credentials = allow_credentials,
        user_verification = UserVerificationRequirement.REQUIRED
    )

@router.get("/generate-registration-options", responses=responses(PublicKeyCredentialCreationOptions))
async def generate_registration_options_request() -> Any:
    """
    Return the current webauthn options.

    *Requirements:* 
    """
    server_name = urlparse(settings.frontend_base_url).hostname
    # TODO: "LAST_CHALLENGES" is for testing only, store in session (db?) later
    #       somehow get userid and username
    challenge = secrets.token_bytes(16)
    user_id = "test" #use from param
    user_name = "test" #use from param

    LAST_CHALLENGES.append(challenge)

    return generate_registration_options(
        rp_id = server_name,
        rp_name = RP_NAME,
        user_id = user_id,
        user_name = user_name,
        challenge = challenge,
        timeout = 12000
    )

@router.post("/verify-authentication")
async def verify_authentication_request(credential: AuthenticationCredential) -> Any:
    """
    Verify login through webauthn

    *Requirements:* 
    """
    server_name = urlparse(settings.frontend_base_url).hostname
    
    # TODO: "LAST_CHALLENGES" is for testing only, get from session (db?) later
    challenge = LAST_CHALLENGES.pop()

    credential.raw_id = base64url_to_bytes(credential.id)
    credential.response.client_data_json = base64url_to_bytes(credential.response.client_data_json.decode("utf-8"))
    credential.response.authenticator_data = base64url_to_bytes(credential.response.authenticator_data.decode("utf-8"))
    credential.response.signature = base64url_to_bytes(credential.response.signature.decode("utf-8"))

    credential_public_key = None
    for reg_info in LAST_REG_INFOS:
        if(reg_info["credentialID"] == credential.raw_id):
            credential_public_key = reg_info["credentialPublicKey"]
    if credential_public_key is None:
        return {"userVerified": False}
    print(credential)
    print(credential_public_key)
    return verify_authentication_response(
        credential = credential,
        expected_challenge = challenge,
        expected_rp_id = server_name,
        expected_origin = settings.frontend_base_url,
        credential_public_key = credential_public_key,
        credential_current_sign_count = 0,
        require_user_verification = True,
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
    
    # TODO: "LAST_CHALLENGES" is for testing only, get from session (db?) later
    challenge = LAST_CHALLENGES.pop()

    verify_resp = verify_registration_response(
        credential = credential,
        expected_challenge = challenge,
        expected_rp_id = serverName,
        expected_origin = settings.frontend_base_url,
        require_user_verification = True,
    )
    
    LAST_REG_INFOS.append({"transports": credential.response.transports, "credentialPublicKey": verify_resp.credential_public_key , "credentialID": verify_resp.credential_id});
    return verify_resp