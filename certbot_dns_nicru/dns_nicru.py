"""DNS Authenticator for nic.ru."""
import logging

import zope.interface
from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from sh_nic_api import DnsApi
from sh_nic_api.exceptions import DnsApiException
from sh_nic_api.models import TXTRecord

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """
    DNS Authenticator for nic.ru
    This Authenticator uses the nic.ru Remote REST API
    to fulfill a dns-01 challenge.
    """

    description = (
        "Obtain certificates using a DNS TXT record "
        "(if you are using nic.ru for DNS)."
    )
    ttl: int = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=180
        )
        add("credentials", help="nic.ru credentials INI file.")

    def more_info(self) -> str:
        return (
            "This plugin configures a DNS TXT record to respond to "
            "a dns-01 challenge using the nic.ru Remote REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "nic.ru credentials INI file",
            {
                "client_id": "The id of application",
                "client_secret": "The token of application",
                "username": "Username for nic.ru Remote API (---/NIC-D).",
                "password": "Password for nic.ru Remote API.",
                "scope": "Scope for access (GET:/dns-master/.+)",
                "service": "Service name",
                "zone": "Zone name",
            },
        )

    def _perform(self, domain: str, validation_name: str, validation: str):
        client = self._get_client()
        logger.info('try add txt record %s for domain %s as %s with key %s', self.get_txt_record_name(validation_name),
                    validation_name, validation)
        try:
            client.add_record(TXTRecord(
                txt=validation,
                ttl=self.ttl,
                name=self.get_txt_record_name(validation_name)
            ))
            client.commit()
        except DnsApiException as e:
            raise errors.PluginError(f"Add record error: {e}, ")

    def _cleanup(self, domain: str, validation_name: str, validation: str):
        if self.credentials is None:
            self._setup_credentials()

        client = self._get_client()
        name = self.get_txt_record_name(validation_name)

        try:
            for record in client.records():
                if record.name != name:
                    continue
                client.delete_record(record_id=record.id)
                client.commit()
        except DnsApiException as e:
            raise errors.PluginError(f"Delete record error: {e}")

    def _get_client(self):
        client = DnsApi(
            client_id=self.credentials.conf("client_id"),
            client_secret=self.credentials.conf("client_secret"),
            username=self.credentials.conf("username"),
            password=self.credentials.conf("password"),
            scope=self.credentials.conf("scope"),
            default_service=self.credentials.conf("service"),
            default_zone=self.credentials.conf("zone"),
        )
        try:
            client.get_token()
        except DnsApiException as e:
            raise errors.PluginError(f"Get token error: {e}")
        return client

    def get_txt_record_name(self, validation_name: str):
        if self.credentials is None:
            self._setup_credentials()
        name = validation_name.replace(self.credentials.conf("zone"), '').strip('.')
        return name
