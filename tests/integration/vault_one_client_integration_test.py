""" Module for integration tests on vault_one_api_client """
import unittest
import os
from http import HTTPStatus

from pyvaultone.vault_one_api_client import VaultOneAPIClient


class VaultOneAPIClientIntegrationTests(unittest.TestCase):
    """ Class to perform integration tests on vault_one_api_client """

    def setUp(self):
        self.api_base_url = os.environ.get("VAULT_ONE_API_BASE_URL")
        VaultOneAPIClient.credentials_manager = {}

    def test_get_credential_secret_successfully_return_status_200(self):
        """ Test successful return for get credential secret """
        client = VaultOneAPIClient(self.api_base_url)
        response = client.get_credential_secret_by_credential_name(
            "Credential Test")

        expected_response = {
            "status": HTTPStatus.OK,
            "data": {
                "username": "username-test",
                "password": "password-test",
                "privateKey": ""
            }
        }

        self.assertIsNotNone(response.get("data"))
        self.assertEqual(200, response.get("status"))
        self.assertDictEqual(expected_response, response)

    def test_get_credential_secret_with_private_key_successfully_return_status_200(self):
        """ Test successful return for get credential secret """
        client = VaultOneAPIClient(self.api_base_url)
        response = client.get_credential_secret_by_credential_name(
            "Credential With Private Key")

        expected_response = {
            "status": HTTPStatus.OK,
            "data": {
                "username": "username",
                "password": "",
                "privateKey": "private-key"
            }
        }

        self.assertIsNotNone(response.get("data"))
        self.assertEqual(200, response.get("status"))
        self.assertDictEqual(expected_response, response)

    def test_get_credential_secret_successfully_return_all_secrets(self):
        """ Test successful return for get credential secret """
        client = VaultOneAPIClient(self.api_base_url)
        response = client.get_all_credential_secrets_by_credential_name(
            "Credential Test")

        expected_response = {
            "status": HTTPStatus.MULTI_STATUS,
            "data": [
                {
                    "status": HTTPStatus.OK,
                    "data": {
                        "username": "username-test",
                        "password": "password-test",
                        "privateKey": ""
                    }
                },
                {
                    "status": HTTPStatus.OK,
                    "data": {
                        "username": "username-1",
                        "password": "password-1",
                        "privateKey": ""
                    }
                }
            ]
        }

        self.assertIsNotNone(response.get("data"))
        self.assertEqual(207, response.get("status"))
        self.assertDictEqual(expected_response, response)

    def test_get_credential_secret_not_found_return_status_code_404(self):
        """ Test not found return for get credential secret """
        client = VaultOneAPIClient(self.api_base_url)
        response = client.get_credential_secret_by_credential_name(
            "Credential Does Not Exist")
        expected_response = {
            "status": 404,
            "data": None
        }
        self.assertDictEqual(expected_response, response)


if __name__ == '__main__':
    unittest.main()
