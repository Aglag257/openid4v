from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.utils import importer
from fedservice.entity import FederationEntity
from idpyoidc.client.configure import Configuration
from idpyoidc.client.oauth2 import Client
from idpyoidc.node import Unit
from requests import request


def build_instance(spec, upstream_get):
    kwargs = spec.get("kwargs", {})
    conf = kwargs.get("config", {})
    if conf == {}:
        conf = kwargs

    # class can be a string (class path) or a class reference
    if isinstance(spec["class"], str):
        _instance = importer(spec["class"])(upstream_get=upstream_get, **conf)
    else:
        _instance = spec["class"](upstream_get=upstream_get, **conf)
    return _instance

class PidEaaHandler(Unit):
    client_type = "oauth2"

    def __init__(
            self,
            config: Optional[Union[dict, Configuration]] = None,
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            key_conf: Optional[dict] = None,
            entity_id: Optional[str] = "",
            **kwargs
    ):
        """

        :type client_type: str
        :param client_type: What kind of client this is. Presently 'oauth2' or 'oidc'
        :param keyjar: A py:class:`idpyoidc.key_jar.KeyJar` instance
        :param config: Configuration information passed on to the
            :py:class:`idpyoidc.client.service_context.ServiceContext`
            initialization
        :param httpc: A HTTP client to use
        :param httpc_params: HTTP request arguments
        :param services: A list of service definitions
        :param jwks_uri: A jwks_uri
        :return: Client instance
        """

        self.entity_id = entity_id or config.get("entity_id")
        self.key_conf = key_conf
        self.config = config

        if httpc:
            self.httpc = httpc
        else:
            self.httpc = request

        self.httpc_params = httpc_params
        self.kwargs = kwargs

        # will create a Key Jar (self.keyjar) as a side effect
        Unit.__init__(self,
                      httpc=self.httpc,
                      httpc_params=self.httpc_params,
                      key_conf=key_conf,
                      issuer_id=entity_id,
                      **kwargs)

        del self.config["key_conf"]
        self._consumer = {}

    def new_consumer(self, issuer_id):
        _consumer = Client(
            config=self.config,
            httpc=self.httpc,
            httpc_params=self.httpc_params,
            upstream_get=self.unit_get,
            entity_id=self.entity_id
        )
        _consumer.context.issuer = issuer_id
        _consumer.context.claims.prefer["client_id"] = _consumer.entity_id
        _consumer.context.provider_info = self.upstream_get("unit")[
            "federation_entity"].get_verified_metadata(issuer_id)["openid_credential_issuer"]
        self._consumer[issuer_id] = _consumer
        return _consumer

    def get_consumer(self, issuer_id):
        return self._consumer.get(issuer_id, None)