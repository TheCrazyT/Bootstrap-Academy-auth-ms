"""Endpoints for webauthn"""

# Some notes:
#  * for local testing, only use "localhost" instead of "127.0.0.1", since ip-addresses do not seem to be supported by webauthn
#  * also make shure that FRONTEND_BASE_URL is "localhost"

from typing import Any

from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    PYDANTIC_V2,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorTransport,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialCreationOptions
)

from fastapi import APIRouter, Body, Request

from ..utils.docs import responses

from ..settings import settings

from urllib.parse import urlparse

router = APIRouter()

#TODO:
# Currently I'm just using example code from: https://github.com/duo-labs/py_webauthn/tree/494373e539050b96130c28477289feec65e5e19f/examples
# But those are only example-values!
# This means that "challenge" etc. will probably need to be generated ...
# That "challenge" would somehow need to be stored (but without login we have no sesssion, yet) ...

@router.get("/generate-authentication-options", responses=responses(PublicKeyCredentialRequestOptions))
async def generate_authentication_options_request() -> Any:
    """
    Return the current webauthn options.

    *Requirements:* 
    """
    serverName = urlparse(settings.frontend_base_url).netloc

    return generate_authentication_options(
        rp_id = serverName,
        challenge = b"1234567890",
        timeout = 12000,
        allow_credentials = [PublicKeyCredentialDescriptor(id=b"1234567890",transports=[AuthenticatorTransport.USB,AuthenticatorTransport.NFC,AuthenticatorTransport.BLE,AuthenticatorTransport.INTERNAL,AuthenticatorTransport.CABLE,AuthenticatorTransport.HYBRID])],
        user_verification = UserVerificationRequirement.REQUIRED
    );

@router.get("/generate-registration-options", responses=responses(PublicKeyCredentialCreationOptions))
async def generate_registration_options_request() -> Any:
    """
    Return the current webauthn options.

    *Requirements:* 
    """
    serverName = urlparse(settings.frontend_base_url).netloc

    return generate_registration_options(
        rp_id = serverName,
        challenge = b"1234567890",
        timeout = 12000,
        allow_credentials = [PublicKeyCredentialDescriptor(id=b"1234567890")],
        user_verification = UserVerificationRequirement.REQUIRED
    );

@router.post("/verify-authentication")
async def verify_authentication_request() -> Any:
    """
    Verify login through webauthn

    *Requirements:* 
    """
    return verify_authentication_response(
        # Demonstrating the ability to handle a stringified JSON version of the WebAuthn response
        credential="""{
            "id": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "rawId": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVBtQWkxUHAxWEw2b0FncTNQV1p0WlBuWmExekZVRG9HYmFRMF9LdlZHMWxGMnMzUnRfM280dVN6Y2N5MHRtY1RJcFRUVDRCVTFULUk0bWFhdm5kalEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "signature": "iOHKX3erU5_OYP_r_9HLZ-CexCE4bQRrxM8WmuoKTDdhAnZSeTP0sjECjvjfeS8MJzN1ArmvV0H0C3yy_FdRFfcpUPZzdZ7bBcmPh1XPdxRwY747OrIzcTLTFQUPdn1U-izCZtP_78VGw9pCpdMsv4CUzZdJbEcRtQuRS03qUjqDaovoJhOqEBmxJn9Wu8tBi_Qx7A33RbYjlfyLm_EDqimzDZhyietyop6XUcpKarKqVH0M6mMrM5zTjp8xf3W7odFCadXEJg-ERZqFM0-9Uup6kJNLbr6C5J4NDYmSm3HCSA6lp2iEiMPKU8Ii7QZ61kybXLxsX4w4Dm3fOLjmDw",
                "userHandle": "T1RWa1l6VXdPRFV0WW1NNVlTMDBOVEkxTFRnd056Z3RabVZpWVdZNFpEVm1ZMk5p"
            },
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
            "clientExtensionResults": {}
        }""",
        expected_challenge=base64url_to_bytes(
            "iPmAi1Pp1XL6oAgq3PWZtZPnZa1zFUDoGbaQ0_KvVG1lF2s3Rt_3o4uSzccy0tmcTIpTTT4BU1T-I4maavndjQ"
        ),
        expected_rp_id="localhost",
        expected_origin="http://localhost:5000",
        credential_public_key=base64url_to_bytes(
            "pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE"
        ),
        credential_current_sign_count=0,
        require_user_verification=True,
    )

@router.post("/verify-registration")
async def verify_registration_request() -> Any:
    """
    Verify registration through webauthn

    *Requirements:* 
    """
    return verify_registration_response(
        # Demonstrating the ability to handle a stringified JSON version of the WebAuthn response
        credential="""{
            "id": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "rawId": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVBtQWkxUHAxWEw2b0FncTNQV1p0WlBuWmExekZVRG9HYmFRMF9LdlZHMWxGMnMzUnRfM280dVN6Y2N5MHRtY1RJcFRUVDRCVTFULUk0bWFhdm5kalEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "signature": "iOHKX3erU5_OYP_r_9HLZ-CexCE4bQRrxM8WmuoKTDdhAnZSeTP0sjECjvjfeS8MJzN1ArmvV0H0C3yy_FdRFfcpUPZzdZ7bBcmPh1XPdxRwY747OrIzcTLTFQUPdn1U-izCZtP_78VGw9pCpdMsv4CUzZdJbEcRtQuRS03qUjqDaovoJhOqEBmxJn9Wu8tBi_Qx7A33RbYjlfyLm_EDqimzDZhyietyop6XUcpKarKqVH0M6mMrM5zTjp8xf3W7odFCadXEJg-ERZqFM0-9Uup6kJNLbr6C5J4NDYmSm3HCSA6lp2iEiMPKU8Ii7QZ61kybXLxsX4w4Dm3fOLjmDw",
                "userHandle": "T1RWa1l6VXdPRFV0WW1NNVlTMDBOVEkxTFRnd056Z3RabVZpWVdZNFpEVm1ZMk5p"
            },
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
            "clientExtensionResults": {}
        }""",
        expected_challenge=base64url_to_bytes(
            "iPmAi1Pp1XL6oAgq3PWZtZPnZa1zFUDoGbaQ0_KvVG1lF2s3Rt_3o4uSzccy0tmcTIpTTT4BU1T-I4maavndjQ"
        ),
        expected_rp_id="localhost",
        expected_origin="http://localhost:5000",
        credential_public_key=base64url_to_bytes(
            "pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE"
        ),
        credential_current_sign_count=0,
        require_user_verification=True,
    )