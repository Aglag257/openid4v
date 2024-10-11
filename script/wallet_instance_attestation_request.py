#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import time
import uuid
from sys import argv
from typing import Any, Dict, List, Optional

from jose import jwk

import jwt
from authlib.jose import JsonWebKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_private_key
from fedservice.utils import get_jwks, make_federation_combo
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from jose import jwk
from jose.utils import base64url_decode

WALLET_CONFIG = {
    "services": {
        "integrity": {
            "class": "openid4v.client.device_integrity_service.IntegrityService"
        },
        "key_attestation": {
            "class": "openid4v.client.device_integrity_service.KeyAttestationService"
        },
        "wallet_instance_attestation": {
            "class": "openid4v.client.wallet_instance_attestation.WalletInstanceAttestation"
        },
        "challenge": {
            "class": "openid4v.client.challenge.ChallengeService"
        },
        "registration": {
            "class": "openid4v.client.registration.RegistrationService"
        }
    }
}

PID_EEA_CONSUMER_CONFIG = {
    "add_ons": {
        "pkce": {
            "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
            "kwargs": {"code_challenge_length": 64,
                       "code_challenge_method": "S256"},
        },
        "dpop": {
            "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
            "kwargs": {
                'dpop_signing_alg_values_supported': ["ES256"]
            }
        }
    },
    "preference": {
        "client_authn_methods": ["private_key_jwt"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "form_post"],
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"]
    },
    "services": {
        "pid_eaa_authorization": {
            "class": "openid4v.client.pid_eaa.Authorization",
            "kwargs": {
                "client_authn_methods": {
                    "client_attestation":
                        "openid4v.client.client_authn.ClientAuthenticationAttestation"
                },
                "default_authn_method": "client_attestation"
            },
        },
        "pid_eaa_token": {
            "class": "openid4v.client.pid_eaa.AccessToken",
            "kwargs": {
                "client_authn_methods": {
                    "client_attestation":
                        "openid4v.client.client_authn.ClientAuthenticationAttestation"},
                "default_authn_method": "client_attestation"
            }
        },
        "credential": {
            "path": "credential",
            "class": 'openid4v.client.pid_eaa.Credential',
            "kwargs": {
                "client_authn_methods": {"dpop_header": "openid4v.client.client_authn.DPoPHeader"},
                "default_authn_method": "dpop_header"
            }
        }
    }
}

def save_key_as_jwk(key):
    # If the key is already in JWK format
    if hasattr(key, 'to_dict'):
        jwk_dict = key.to_dict()
    # If the key has a direct JSON representation
    elif hasattr(key, 'to_json'):
        jwk_dict = json.loads(key.to_json())
    # If the key can be exported to PEM
    elif hasattr(key, 'private_bytes'):
        # For cryptography.io keys
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        jwk_dict = jwk.construct(pem, algorithm='RS256').to_dict()
    else:
        raise ValueError("Unsupported key type")
    
    # Save the JWK to a file
    with open('key.jwk', 'w') as f:
        json.dump(jwk_dict, f, indent=2)

def export_tokens(wallet_attestation_jwt: str, jwk_thumbprint: str, wia_pop: str, output_path: str) -> None:
    """
    Export the tokens to a JSON file that can be read by the Node.js script.
    
    Args:
        wallet_attestation_jwt: The wallet attestation JWT
        jwk_thumbprint: The JWK thumbprint
        wia_pop: The WIA-PoP token
        output_path: Path where to save the JSON file
    """
    tokens = {
        "walletAttestationJWT": wallet_attestation_jwt,
        "jwkThumbprint": jwk_thumbprint,
        "wiaPop": wia_pop
    }
    
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Write the tokens to a JSON file
    with open(output_path, 'w') as f:
        json.dump(tokens, f, indent=2)


def load_ephemeral_key(ephemeral_key):

    return ephemeral_key.private_key()

def calculate_jwk_thumbprint(ephemeral_key):
    # Get the public key components from the ECKey object
    public_key_dict = ephemeral_key.serialize(private=False)
    
    # Construct a JWK dictionary for the public key part
    jwk = {
        "kty": public_key_dict['kty'],
        "crv": public_key_dict['crv'],
        "x": public_key_dict['x'],
        "y": public_key_dict['y']
    }
    
    # Create canonical form of the JWK
    jwk_json = '{"crv":"%s","kty":"%s","x":"%s","y":"%s"}' % (
        jwk['crv'], jwk['kty'], jwk['x'], jwk['y']
    )
    
    # Calculate thumbprint
    jwk_thumbprint = hashlib.sha256(jwk_json.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(jwk_thumbprint).rstrip(b'=').decode('utf-8')

def create_wia_pop_jwt(ephemeral_key):
    # Get the private key directly from the ECKey object
    private_key = load_ephemeral_key(ephemeral_key)
    
    # Calculate the JWK Thumbprint
    jwk_thumbprint = calculate_jwk_thumbprint(ephemeral_key)
    print('JWK Thumbprint:')
    print(jwk_thumbprint)
    # Prepare payload
    payload = {
        "iss": jwk_thumbprint,
        "aud": "https://openidfed-test-1.sunet.se:5001/",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "jti": str(uuid.uuid4())
    }
    
    # # Sign JWT
    # wia_pop_jwt = jwt.encode(
    #     payload,
    #     private_key,
    #     algorithm="ES256",
    #     headers={
    #         "typ": "jwt-client-attestation-pop",
    #         "alg": "ES256",
    #         "kid": jwk_thumbprint
    #     }
    # )
        # Sign JWT
    wia_pop_jwt = jwt.encode(
        payload,
        private_key,
        algorithm="ES256",
        headers={
            "alg": "ES256",
        }
    )
    
    return wia_pop_jwt
def wallet_setup(entity_id: str,
                 authority_hints: Optional[List[str]] = None,
                 trust_anchors: Optional[dict] = None,
                 preference: Optional[dict] = None,
                 endpoints: Optional[list] = None,
                 key_config: Optional[dict] = None,
                 entity_type_config: Optional[dict] = None,
                 services: Optional[list] = None
                 ):
    if not key_config:
        key_config = {"key_defs": DEFAULT_KEY_DEFS}
    if not services:
        services = [
            "entity_configuration",
            "entity_statement",
            "list",
            "trust_mark_status"
        ]
    if not entity_type_config:
        entity_type_config = {
            "wallet": WALLET_CONFIG,
            "pid_eaa_consumer": PID_EEA_CONSUMER_CONFIG
        }
    else:
        if "wallet" not in entity_type_config:
            entity_type_config["wallet"] = WALLET_CONFIG
        if "pid_eaa_consumer" not in entity_type_config:
            entity_type_config["pid_eaa_consumer"] = PID_EEA_CONSUMER_CONFIG

    wallet = make_federation_combo(
        entity_id,
        preference=preference,
        key_config=key_config,
        httpc_params={"verify": False},
        trust_anchors=trust_anchors,
        endpoints=endpoints,
        services=services,
        entity_type={
            "wallet": {
                "class": "openid4v.client.Wallet",
                "kwargs": {
                    "config": entity_type_config["wallet"],
                    "key_conf": {
                        "key_defs": [
                            {
                                "type": "EC",
                                "crv": "P-256",
                                "use": ["sig"]
                            }
                        ]
                    }
                }
            },
            "pid_eaa_consumer": {
                'class': "openid4v.client.pid_eaa_consumer.PidEaaHandler",
                'kwargs': {
                    'config': entity_type_config["pid_eaa_consumer"]
                }
            }
        }
    )

    return wallet


def main(wallet_provider_id: str, trust_anchors: dict):
    _combo = wallet_setup(wallet_provider_id, trust_anchors=trust_anchors)
    _wallet = _combo["wallet"]

    # create an ephemeral key
    _ephemeral_key = _wallet.mint_new_key()
    save_key_as_jwk(_ephemeral_key)

    # load it in the wallet KeyJar
    _jwks = {"keys": [_ephemeral_key.serialize(private=True)]}
    _wallet.context.keyjar.import_jwks(_jwks, _wallet.entity_id)
    _wallet.context.ephemeral_key = {_ephemeral_key.kid: _ephemeral_key}

    # Use the federation to figure out information about the wallet provider
    trust_chains = _wallet.get_trust_chains(wallet_provider_id)

    # load the wallet provider keys
    get_jwks(_wallet, _wallet.context.keyjar, trust_chains[0].metadata['wallet_provider'],
             wallet_provider_id)

    war_payload = {
        "challenge": "__not__applicable__",
        "hardware_signature": "__not__applicable__",
        "integrity_assertion": "__not__applicable__",
        "hardware_key_tag": "__not__applicable__",
        "cnf": {
            "jwk": _ephemeral_key.serialize()
        },
        "vp_formats_supported": {
            "jwt_vc_json": {
                "alg_values_supported": ["ES256K", "ES384"],
            },
            "jwt_vp_json": {
                "alg_values_supported": ["ES256K", "EdDSA"],
            },
        }
    }

    # The service I use to deal with sending the request and parsing the result
    _service = _wallet.get_service('wallet_instance_attestation')
    _service.wallet_provider_id = wallet_provider_id

    _info = _service.get_request_parameters(request_args=war_payload,
                                            endpoint=trust_chains[0].metadata['wallet_provider'][
                                                "token_endpoint"],
                                            ephemeral_key=_ephemeral_key)

    # print information that is used to send the request to the Wallet Provider
    print(_info)

    resp = _wallet.service_request(_service, response_body_type='application/jwt', **_info)

    wia_pop = create_wia_pop_jwt(_ephemeral_key)

    #assertion = f"{str(resp)}~{str(wia_pop)}"
    
    #print('BLAH', str(resp))
    # Extract the individual components
    wallet_attestation_jwt = str(resp)
    jwk_thumbprint = calculate_jwk_thumbprint(_ephemeral_key)
    
    # Export the tokens to a JSON file
    output_path = os.path.join(os.path.dirname(__file__), 'tokens.json')
    export_tokens(wallet_attestation_jwt, jwk_thumbprint, wia_pop, output_path)
    

    print('wia_pop')
    print(wia_pop)
    # assertion = f"{str(resp)}~{str(wia_pop)}"
    # return assertion
    return resp


if __name__ == "__main__":
    # Values from https://wiki.sunet.se/display/Projekt/EUDIW+pilot+setup
    # https://openidfed-test-1.sunet.se:5001/
    wallet_provider_id = argv[1]
    # trust_anchors_keys.json
    trust_anchors_file = argv[2]

    trust_anchors = json.load(open(trust_anchors_file, "r"))

    print(main(wallet_provider_id, trust_anchors))
