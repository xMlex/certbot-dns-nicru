"""Tests for certbot_dns_nicru"""

import sys
import mock

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util
from certbot._internal.display import obj

from certbot_dns_nicru.dns_nicru import Authenticator


class AuthenticatorTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write(
            {
                "dns_nicru_username": "fake-user",
                "dns_nicru_password": "fake-password",
                "dns_nicru_client_id": "fake-client-id",
                "dns_nicru_client_secret": "fake-client-secret",
                "dns_nicru_scope": "empty",
                "dns_nicru_service": "service",
                "dns_nicru_zone": "zone"
            },
            path,
        )

        super(AuthenticatorTest, self).setUp()
        self.config = mock.MagicMock(
            dns_nicru_credentials=path, dns_nicru_propagation_seconds=0
        )  # don't wait during tests

        self.auth = Authenticator(self.config, "dns_nicru")

        self.mock_client = mock.MagicMock()
        self.auth._get_client = mock.MagicMock(return_value=self.mock_client)

        obj.set_display(obj.FileDisplay(sys.stdout, False))

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_record(mock.ANY), mock.call.commit()]
        self.assertEqual(expected, self.mock_client.mock_calls)
        self.assertEqual(
            "_acme-challenge", self.mock_client.mock_calls[0][1][0].name
        )

    def test_cleanup(self):
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])


class AuthenticatorExtendedTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    """Extended test suite for Authenticator with comprehensive coverage."""

    def setUp(self):
        super(AuthenticatorExtendedTest, self).setUp()

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write(
            {
                "dns_nicru_username": "test-user",
                "dns_nicru_password": "test-password",
                "dns_nicru_client_id": "test-client-id",
                "dns_nicru_client_secret": "test-client-secret",
                "dns_nicru_scope": "GET:/dns-master/.+",
                "dns_nicru_service": "test-service",
                "dns_nicru_zone": "example.com"
            },
            path,
        )

        self.config = mock.MagicMock(
            dns_nicru_credentials=path, dns_nicru_propagation_seconds=0
        )

        self.auth = Authenticator(self.config, "dns_nicru")
        self.mock_client = mock.MagicMock()
        self.auth._get_client = mock.MagicMock(return_value=self.mock_client)

        obj.set_display(obj.FileDisplay(sys.stdout, False))

    def test_more_info_returns_description(self):
        """Test that more_info() returns a non-empty string."""
        info = self.auth.more_info()
        self.assertIsInstance(info, str)
        self.assertGreater(len(info), 0)
        self.assertIn("dns-01", info.lower())
        self.assertIn("nic.ru", info.lower())

    def test_description_is_set(self):
        """Test that description attribute is properly set."""
        self.assertTrue(hasattr(Authenticator, 'description'))
        self.assertIsInstance(Authenticator.description, str)
        self.assertGreater(len(Authenticator.description), 0)

    def test_ttl_default_value(self):
        """Test that TTL has a reasonable default value."""
        self.assertTrue(hasattr(Authenticator, 'ttl'))
        self.assertEqual(Authenticator.ttl, 60)
        self.assertIsInstance(Authenticator.ttl, int)

    def test_credentials_initially_none(self):
        """Test that credentials are None before setup."""
        auth = Authenticator(self.config, "dns_nicru")
        self.assertIsNone(auth.credentials)

    def test_setup_credentials_configures_properly(self):
        """Test that _setup_credentials initializes credentials object."""
        self.auth._setup_credentials()
        self.assertIsNotNone(self.auth.credentials)

    def test_get_txt_record_name_strips_zone(self):
        """Test that get_txt_record_name correctly strips zone suffix."""
        self.auth._setup_credentials()
        
        # Test with zone at end
        result = self.auth.get_txt_record_name("_acme-challenge.subdomain.example.com")
        self.assertEqual(result, "_acme-challenge.subdomain")
        
        # Test with just zone
        result = self.auth.get_txt_record_name("example.com")
        self.assertEqual(result, "")

    def test_get_txt_record_name_handles_dots_properly(self):
        """Test that get_txt_record_name handles leading/trailing dots."""
        self.auth._setup_credentials()
        
        # Should strip trailing dots
        result = self.auth.get_txt_record_name("_acme-challenge.example.com.")
        self.assertNotIn(".", result.split("_acme-challenge")[-1].strip("_acme-challenge"))

    def test_get_txt_record_name_with_subdomain(self):
        """Test get_txt_record_name with various subdomain structures."""
        self.auth._setup_credentials()
        
        # Multi-level subdomain
        result = self.auth.get_txt_record_name("_acme-challenge.sub1.sub2.example.com")
        self.assertEqual(result, "_acme-challenge.sub1.sub2")

    def test_perform_with_api_exception(self):
        """Test that _perform raises PluginError on DnsApiException."""
        from sh_nic_api.exceptions import DnsApiException
        from certbot import errors
        
        self.auth._setup_credentials()
        self.mock_client.add_record.side_effect = DnsApiException("API Error")
        
        with self.assertRaises(errors.PluginError) as context:
            self.auth._perform("example.com", "_acme-challenge.example.com", "validation_token")
        
        self.assertIn("Add record error", str(context.exception))

    def test_perform_calls_add_record_with_correct_parameters(self):
        """Test that _perform calls add_record with TXTRecord object."""
        from sh_nic_api.models import TXTRecord
        
        self.auth._setup_credentials()
        validation = "test_validation_string"
        validation_name = "_acme-challenge.example.com"
        
        self.auth._perform("example.com", validation_name, validation)
        
        # Verify add_record was called
        self.mock_client.add_record.assert_called_once()
        
        # Get the argument passed to add_record
        call_args = self.mock_client.add_record.call_args[0][0]
        self.assertIsInstance(call_args, TXTRecord)
        self.assertEqual(call_args.txt, validation)
        self.assertEqual(call_args.ttl, 60)

    def test_perform_calls_commit_after_add(self):
        """Test that _perform calls commit after adding record."""
        self.auth._setup_credentials()
        
        self.auth._perform("example.com", "_acme-challenge.example.com", "validation")
        
        # Verify commit was called after add_record
        self.mock_client.commit.assert_called_once()
        self.assertEqual(self.mock_client.method_calls[0][0], 'add_record')
        self.assertEqual(self.mock_client.method_calls[1][0], 'commit')

    def test_cleanup_with_matching_record(self):
        """Test that _cleanup deletes matching TXT records."""
        from sh_nic_api.models import TXTRecord
        
        self.auth._setup_credentials()
        
        # Mock records returned by API
        mock_record_1 = mock.MagicMock()
        mock_record_1.name = "_acme-challenge"
        mock_record_1.id = "record-1"
        
        mock_record_2 = mock.MagicMock()
        mock_record_2.name = "other-record"
        mock_record_2.id = "record-2"
        
        self.mock_client.records.return_value = [mock_record_1, mock_record_2]
        
        self.auth._cleanup("example.com", "_acme-challenge.example.com", "validation")
        
        # Should delete only the matching record
        self.mock_client.delete_record.assert_called_once_with(record_id="record-1")
        self.mock_client.commit.assert_called_once()

    def test_cleanup_with_no_matching_record(self):
        """Test that _cleanup handles case with no matching records."""
        self.auth._setup_credentials()
        
        # Mock no matching records
        mock_record = mock.MagicMock()
        mock_record.name = "other-record"
        mock_record.id = "record-1"
        
        self.mock_client.records.return_value = [mock_record]
        
        # Should not raise an error
        self.auth._cleanup("example.com", "_acme-challenge.example.com", "validation")
        
        # Should not call delete_record
        self.mock_client.delete_record.assert_not_called()
        self.mock_client.commit.assert_not_called()

    def test_cleanup_with_api_exception(self):
        """Test that _cleanup raises PluginError on DnsApiException."""
        from sh_nic_api.exceptions import DnsApiException
        from certbot import errors
        
        self.auth._setup_credentials()
        self.mock_client.records.side_effect = DnsApiException("API Error")
        
        with self.assertRaises(errors.PluginError) as context:
            self.auth._cleanup("example.com", "_acme-challenge.example.com", "validation")
        
        self.assertIn("Delete record error", str(context.exception))

    def test_cleanup_deletes_multiple_matching_records(self):
        """Test that _cleanup deletes all matching TXT records."""
        self.auth._setup_credentials()
        
        # Mock multiple matching records
        mock_record_1 = mock.MagicMock()
        mock_record_1.name = "_acme-challenge"
        mock_record_1.id = "record-1"
        
        mock_record_2 = mock.MagicMock()
        mock_record_2.name = "_acme-challenge"
        mock_record_2.id = "record-2"
        
        mock_record_3 = mock.MagicMock()
        mock_record_3.name = "other-record"
        mock_record_3.id = "record-3"
        
        self.mock_client.records.return_value = [mock_record_1, mock_record_2, mock_record_3]
        
        self.auth._cleanup("example.com", "_acme-challenge.example.com", "validation")
        
        # Should delete both matching records
        self.assertEqual(self.mock_client.delete_record.call_count, 2)
        self.assertEqual(self.mock_client.commit.call_count, 2)

    def test_get_client_creates_dns_api_instance(self):
        """Test that _get_client creates DnsApi with correct credentials."""
        from sh_nic_api import DnsApi
        
        self.auth._setup_credentials()
        
        # Temporarily replace _get_client to test actual implementation
        self.auth._get_client = Authenticator._get_client.__get__(self.auth, Authenticator)
        
        with mock.patch('certbot_dns_nicru.dns_nicru.DnsApi') as mock_dns_api:
            mock_api_instance = mock.MagicMock()
            mock_dns_api.return_value = mock_api_instance
            
            client = self.auth._get_client()
            
            # Verify DnsApi was instantiated with correct parameters
            mock_dns_api.assert_called_once()
            call_kwargs = mock_dns_api.call_args[1]
            
            self.assertEqual(call_kwargs['client_id'], 'test-client-id')
            self.assertEqual(call_kwargs['client_secret'], 'test-client-secret')
            self.assertEqual(call_kwargs['username'], 'test-user')
            self.assertEqual(call_kwargs['password'], 'test-password')
            self.assertEqual(call_kwargs['scope'], 'GET:/dns-master/.+')
            self.assertEqual(call_kwargs['default_service'], 'test-service')
            self.assertEqual(call_kwargs['default_zone'], 'example.com')
            
            # Verify get_token was called
            mock_api_instance.get_token.assert_called_once()

    def test_get_client_handles_token_error(self):
        """Test that _get_client raises PluginError on token retrieval failure."""
        from sh_nic_api.exceptions import DnsApiException
        from certbot import errors
        
        self.auth._setup_credentials()
        self.auth._get_client = Authenticator._get_client.__get__(self.auth, Authenticator)
        
        with mock.patch('certbot_dns_nicru.dns_nicru.DnsApi') as mock_dns_api:
            mock_api_instance = mock.MagicMock()
            mock_api_instance.get_token.side_effect = DnsApiException("Token error")
            mock_dns_api.return_value = mock_api_instance
            
            with self.assertRaises(errors.PluginError) as context:
                self.auth._get_client()
            
            self.assertIn("Get token error", str(context.exception))

    def test_add_parser_arguments_sets_credentials(self):
        """Test that add_parser_arguments adds credentials argument."""
        mock_add = mock.MagicMock()
        
        Authenticator.add_parser_arguments(mock_add)
        
        # Verify credentials argument was added
        calls = [str(call) for call in mock_add.call_args_list]
        credentials_added = any('credentials' in str(call) for call in calls)
        self.assertTrue(credentials_added, "credentials argument should be added")

    def test_add_parser_arguments_sets_propagation_seconds(self):
        """Test that add_parser_arguments sets default propagation seconds."""
        mock_add = mock.MagicMock()
        
        # Get the parent class method call
        with mock.patch.object(dns_common.DNSAuthenticator, 'add_parser_arguments') as mock_parent:
            Authenticator.add_parser_arguments(mock_add)
            
            # Verify parent was called with default_propagation_seconds
            mock_parent.assert_called_once()
            call_kwargs = mock_parent.call_args[1]
            self.assertIn('default_propagation_seconds', call_kwargs)
            self.assertEqual(call_kwargs['default_propagation_seconds'], 180)

    def test_credentials_conf_method_accessible(self):
        """Test that credentials object has conf method for accessing values."""
        self.auth._setup_credentials()
        
        # The conf method should be callable
        self.assertTrue(hasattr(self.auth.credentials, 'conf'))
        self.assertTrue(callable(self.auth.credentials.conf))

    def test_perform_with_empty_validation(self):
        """Test _perform behavior with empty validation string."""
        self.auth._setup_credentials()
        
        # Should still attempt to add record even with empty validation
        self.auth._perform("example.com", "_acme-challenge.example.com", "")
        
        self.mock_client.add_record.assert_called_once()
        call_args = self.mock_client.add_record.call_args[0][0]
        self.assertEqual(call_args.txt, "")

    def test_perform_with_special_characters_in_validation(self):
        """Test _perform with special characters in validation string."""
        self.auth._setup_credentials()
        
        special_validation = "abc123!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        self.auth._perform("example.com", "_acme-challenge.example.com", special_validation)
        
        self.mock_client.add_record.assert_called_once()
        call_args = self.mock_client.add_record.call_args[0][0]
        self.assertEqual(call_args.txt, special_validation)

    def test_cleanup_with_empty_records_list(self):
        """Test _cleanup when API returns empty records list."""
        self.auth._setup_credentials()
        
        self.mock_client.records.return_value = []
        
        # Should not raise an error
        self.auth._cleanup("example.com", "_acme-challenge.example.com", "validation")
        
        self.mock_client.delete_record.assert_not_called()

    def test_get_txt_record_name_with_multiple_dots(self):
        """Test get_txt_record_name with validation names containing multiple dots."""
        self.auth._setup_credentials()
        
        result = self.auth.get_txt_record_name("_acme-challenge.a.b.c.d.example.com")
        self.assertEqual(result, "_acme-challenge.a.b.c.d")

    def test_credentials_setup_idempotent(self):
        """Test that calling _setup_credentials multiple times is safe."""
        self.auth._setup_credentials()
        first_credentials = self.auth.credentials
        
        self.auth._setup_credentials()
        second_credentials = self.auth.credentials
        
        # Should have credentials set both times
        self.assertIsNotNone(first_credentials)
        self.assertIsNotNone(second_credentials)


class AuthenticatorEdgeCasesTest(test_util.TempDirTestCase):
    """Test edge cases and error conditions for Authenticator."""

    def test_authenticator_initialization_without_credentials(self):
        """Test that Authenticator can be initialized without immediate credential access."""
        config = mock.MagicMock(dns_nicru_propagation_seconds=0)
        auth = Authenticator(config, "dns_nicru")
        
        self.assertIsNotNone(auth)
        self.assertIsNone(auth.credentials)

    def test_get_txt_record_name_calls_setup_if_needed(self):
        """Test that get_txt_record_name sets up credentials if not already done."""
        path = os.path.join(self.tempdir, "test.ini")
        dns_test_common.write(
            {
                "dns_nicru_username": "user",
                "dns_nicru_password": "pass",
                "dns_nicru_client_id": "id",
                "dns_nicru_client_secret": "secret",
                "dns_nicru_scope": "scope",
                "dns_nicru_service": "service",
                "dns_nicru_zone": "example.com"
            },
            path,
        )
        
        config = mock.MagicMock(dns_nicru_credentials=path)
        auth = Authenticator(config, "dns_nicru")
        
        # Credentials should be None initially
        self.assertIsNone(auth.credentials)
        
        # Calling get_txt_record_name should set up credentials
        result = auth.get_txt_record_name("test.example.com")
        
        self.assertIsNotNone(auth.credentials)

    def test_cleanup_sets_up_credentials_if_needed(self):
        """Test that _cleanup sets up credentials if not already initialized."""
        path = os.path.join(self.tempdir, "test.ini")
        dns_test_common.write(
            {
                "dns_nicru_username": "user",
                "dns_nicru_password": "pass",
                "dns_nicru_client_id": "id",
                "dns_nicru_client_secret": "secret",
                "dns_nicru_scope": "scope",
                "dns_nicru_service": "service",
                "dns_nicru_zone": "example.com"
            },
            path,
        )
        
        config = mock.MagicMock(dns_nicru_credentials=path)
        auth = Authenticator(config, "dns_nicru")
        
        mock_client = mock.MagicMock()
        mock_client.records.return_value = []
        auth._get_client = mock.MagicMock(return_value=mock_client)
        
        # Credentials should be None initially
        self.assertIsNone(auth.credentials)
        
        # Calling _cleanup should set up credentials
        auth._cleanup("example.com", "_acme-challenge.example.com", "validation")
        
        self.assertIsNotNone(auth.credentials)


if __name__ == '__main__':
    import unittest
    unittest.main()
