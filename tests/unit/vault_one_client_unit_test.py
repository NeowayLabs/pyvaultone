""" Module for unit tests on vault_one_api_client """
import os
import json
import base64
import unittest
from http import HTTPStatus
from unittest import mock
import httpretty

from pyvaultone.vault_one_api_client import VaultOneAPIClient
from pyvaultone.vault_one_api_client import _send_not_success_response
from pyvaultone.vault_one_api_client import get_json_login

_API_BASE_URL = os.environ.get("VAULT_ONE_API_BASE_URL")

def register_authenticate_url_success():
    """ Register successful authenticate request using httpretty """
    body_request = {
        "userNameOrEmailAddress": "username",
        "password": "password"
    }

    httpretty.register_uri(
        method=httpretty.POST,
        uri=f"{_API_BASE_URL}/api/TokenAuth/Authenticate",
        body=json.dumps(body_request),
        responses=[
            httpretty.core.httpretty.Response(
                '{"result": {"accessToken": "token-success", "userId": 1}}',
                status=HTTPStatus.OK
            )
        ]
    )


def register_authenticate_url_failure():
    """ Register failure authenticate request using httpretty """
    body_request = {
        "userNameOrEmailAddress": "username",
        "password": "password"
    }

    httpretty.register_uri(
        method=httpretty.POST,
        uri=f"{_API_BASE_URL}/api/TokenAuth/Authenticate",
        body=json.dumps(body_request),
        responses=[
            httpretty.core.httpretty.Response(
                "",
                status=HTTPStatus.NOT_FOUND
            )
        ]
    )


def register_get_credential_by_filter_success():
    """ Register successful get credential by filter using httpretty """
    httpretty.register_uri(
        method=httpretty.GET,
        uri=(f"{_API_BASE_URL}/api/services/app/Credentials"
             "/GetAllCredentials?Filter=Credential%20Test"),
        responses=[
            httpretty.core.httpretty.Response(
                '{"result":{"items":[{"id":"credential-id","name":"credential-name"}]}}'
            )
        ],
        match_querystring=True
    )


def register_get_credential_by_filter_all_credentials_success():
    """ Register successful get credential by filter using httpretty """
    httpretty.register_uri(
        method=httpretty.GET,
        uri=(f"{_API_BASE_URL}/api/services/app/Credentials"
             "/GetAllCredentials?Filter=Credential%20Test"),
        responses=[
            httpretty.core.httpretty.Response(
                '{"result":{"items":[{"id":"credential-id","name":"credential-name"},'
                '{"id":"credential-id","name":"credential-name"}]}}'
            )
        ],
        match_querystring=True
    )


def register_get_credential_by_filter_return_not_found():
    """ Register failure get credential by filter using httpretty """
    httpretty.register_uri(
        method=httpretty.GET,
        uri=(f"{_API_BASE_URL}/api/services/app/Credentials"
             "/GetAllCredentials?Filter=Credential%20Test"),
        responses=[
            httpretty.core.httpretty.Response(
                "",
                status=HTTPStatus.NOT_FOUND
            )
        ],
        match_querystring=True
    )


def register_get_credential_by_filter_unauthorized():
    """ Register failure get credential by filter return unauthorized using httpretty """
    httpretty.register_uri(
        method=httpretty.GET,
        uri=(f"{_API_BASE_URL}/api/services/app/Credentials"
             "/GetAllCredentials?Filter=Credential%20Test"),
        responses=[
            httpretty.core.httpretty.Response(
                "",
                status=HTTPStatus.UNAUTHORIZED
            )
        ],
        match_querystring=True
    )


def register_get_credential_secret_by_credential_id_success():
    """ Register successful get credential secret by id using httpretty """
    httpretty.register_uri(
        method=httpretty.GET,
        uri=(f"{_API_BASE_URL}/api/services/app/Credentials"
             "/GetCredentialSecret?CredentialId=credential-id"),
        responses=[
            httpretty.core.httpretty.Response(
                '{"result":{"username":"username","pass":"password","privateKey":null}}'
            )
        ],
        match_querystring=True
    )


def register_get_credential_secret_with_private_key_by_credential_id_success():
    """ Register successful get credential secret by id using httpretty """
    httpretty.register_uri(
        method=httpretty.GET,
        uri=(f"{_API_BASE_URL}/api/services/app/Credentials"
             "/GetCredentialSecret?CredentialId=credential-id-with-private-key"),
        responses=[
            httpretty.core.httpretty.Response(
                '{"result":{"username":"username","pass":null,"privateKey":"key"}}'
            )
        ],
        match_querystring=True
    )


def register_get_credential_secret_by_credential_id_failure():
    """ Register failure get credential secret by id using httpretty """
    httpretty.register_uri(
        method=httpretty.GET,
        uri=(f"{_API_BASE_URL}/api/services/app/Credentials"
             "/GetCredentialSecret?CredentialId=credential-id"),
        responses=[
            httpretty.core.httpretty.Response(
                "",
                status=HTTPStatus.NOT_FOUND
            )
        ],
        match_querystring=True
    )


def register_get_credential_secret_by_credential_id_without_result():
    """ Register failure get credential secret by id using httpretty """
    httpretty.register_uri(
        method=httpretty.GET,
        uri=(f"{_API_BASE_URL}/api/services/app/Credentials"
             "/GetCredentialSecret?CredentialId=credential-id-without-result"),
        responses=[
            httpretty.core.httpretty.Response(
                '{"resultado":{"username":"username","password":"password","privateKey":null}}'
            )
        ],
        match_querystring=True
    )


def register_get_credential_secret_by_credential_id_with_unexpected_result():
    """ Register failure get credential secret by id using httpretty """
    httpretty.register_uri(
        method=httpretty.GET,
        uri=(f"{_API_BASE_URL}/api/services/app/Credentials"
             "/GetCredentialSecret?CredentialId=credential-id-unexpected-result"),
        responses=[
            httpretty.core.httpretty.Response(
                '{"result":{"usuario":"username","senha":"password","chavePrivada":null}}'
            )
        ],
        match_querystring=True
    )


class VaultOneAPIClientUnitTests(unittest.TestCase):
    """ Class to perform unit tests on the VaultOneAPIClient """

    def setUp(self):
        self.api_username = base64.b64decode(os.environ.get(
            "VAULT_ONE_API_USERNAME")).decode('utf-8').strip()
        self.api_password = base64.b64decode(os.environ.get(
            "VAULT_ONE_API_PASSWORD")).decode('utf-8').strip()


    def tearDown(self):
        VaultOneAPIClient.credentials_manager = {}

    def test_send_not_success_response_correctly(self):
        """ Test successful not 200 response """
        not_success_response = _send_not_success_response(400)
        expected_response = {
            "status": HTTPStatus.BAD_REQUEST,
            "data": None
        }
        self.assertDictEqual(not_success_response, expected_response)

    def test_get_json_login(self):
        """ Test successful convert username and password to authorize json """
        expected_response = {
            "usernameOrEmailAddress": "user-test",
            "password": "pass-test"
        }

        self.assertDictEqual(
            expected_response, get_json_login("user-test", "pass-test"))

    @httpretty.activate
    def test_authorize_correct_username_and_password_return_status_code_200(self):
        """ Test successful authorize request """
        register_authenticate_url_success()
        client = VaultOneAPIClient(_API_BASE_URL)
        response = client.authorize(self.api_username, self.api_password)
        expected_headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }
        self.assertIsNotNone(response.get("data"))
        self.assertIn("accessToken", response.get("data", {}))
        self.assertEqual(HTTPStatus.OK, response.get("status"))
        self.assertEqual(
            expected_headers["User-Agent"], client.headers["User-Agent"])
        self.assertEqual(
            expected_headers["Content-Type"], client.headers["Content-Type"])
        self.assertIn("authorization", client.headers)

    @httpretty.activate
    def test_authorize_incorrect_username_and_password_return_status_code_not_200(self):
        """ Test failure authorize request """
        register_authenticate_url_failure()
        client = VaultOneAPIClient(_API_BASE_URL)
        response = client.authorize("anyuser", "anypassword")
        self.assertIsNone(response.get("data"))
        self.assertNotEqual(HTTPStatus.OK, response.get("status"))

    @httpretty.activate
    def test_get_credential_by_filter_return_status_code_200(self):
        """ Test successful get credential by filter """
        register_get_credential_by_filter_success()
        client = VaultOneAPIClient(_API_BASE_URL)
        client.headers = {
            "authorization": "Bearer auth-token",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }
        response = client.get_credential_by_filter(
            "Credential Test")

        expected_data = {
            "id": "credential-id",
            "name": "credential-name"
        }

        self.assertEqual(HTTPStatus.OK, response.get("status"))
        self.assertEqual(expected_data, response.get("data", []))

    @httpretty.activate
    def test_get_credential_by_filter_return_all_credentials(self):
        """ Test successful get all credentials """
        register_get_credential_by_filter_all_credentials_success()
        client = VaultOneAPIClient(_API_BASE_URL)
        client.headers = {
            "authorization": "Bearer auth-token",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }

        response = client.get_all_credentials_by_filter("Credential Test")

        expected_data = [
            {
                "id": "credential-id",
                "name": "credential-name"
            },
            {
                "id": "credential-id",
                "name": "credential-name"
            }
        ]

        self.assertEqual(HTTPStatus.OK, response.get("status"))
        self.assertEqual(expected_data, response.get("data", []))

    @httpretty.activate
    def test_get_credential_by_filter_noheaders_return_status_400(self):
        """ Test failure get credential by filter return bad request with no headers """
        register_get_credential_by_filter_success()
        client = VaultOneAPIClient(_API_BASE_URL)
        response = client.get_credential_by_filter(
            "Credential Test")

        self.assertEqual(HTTPStatus.BAD_REQUEST, response.get("status"))
        self.assertIsNone(response.get("data", {}))

    @httpretty.activate
    def test_get_credential_secret_by_credential_id_return_status_code_200(self):
        """ Test successful get credential secret by id """

        register_get_credential_secret_by_credential_id_success()
        register_get_credential_secret_with_private_key_by_credential_id_success()

        client = VaultOneAPIClient(_API_BASE_URL)
        client.headers = {
            "authorization": "Bearer auth-token",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }

        response_pass = client.get_credential_secret_by_credential_id(
            "credential-id")
        expected_data_pass = {
            "username": "username",
            "password": "password",
            "privateKey": ""
        }

        response_private_key = client.get_credential_secret_by_credential_id(
            "credential-id-with-private-key")
        expected_data_private_key = {
            "username": "username",
            "password": "",
            "privateKey": "key"
        }

        self.assertEqual(HTTPStatus.OK, response_pass.get("status"))
        self.assertDictEqual(expected_data_pass, response_pass.get("data", {}))

        self.assertEqual(HTTPStatus.OK, response_private_key.get("status"))
        self.assertDictEqual(expected_data_private_key, response_private_key.get("data", {}))

    @httpretty.activate
    def test_get_credential_secret_by_credential_id_return_errors_status_code(self):
        """ Test failure get credential secret by id return not found """

        register_get_credential_secret_by_credential_id_failure()
        register_get_credential_secret_by_credential_id_without_result()
        register_get_credential_secret_by_credential_id_with_unexpected_result()

        client = VaultOneAPIClient(_API_BASE_URL)
        client.headers = {
            "authorization": "Bearer auth-token",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }

        response = client.get_credential_secret_by_credential_id(
            "credential-id")
        self.assertEqual(HTTPStatus.NOT_FOUND, response.get("status"))
        self.assertIsNone(response.get("data"))

        response = client.get_credential_secret_by_credential_id(
            "credential-id-without-result")
        self.assertEqual(HTTPStatus.INTERNAL_SERVER_ERROR, response.get("status"))
        self.assertIsNone(response.get("data"))

        response = client.get_credential_secret_by_credential_id(
            "credential-id-unexpected-result")
        expected_data = {
            "username": "",
            "password": "",
            "privateKey": ""
        }
        self.assertEqual(HTTPStatus.OK, response.get("status"))
        self.assertDictEqual(expected_data, response.get("data", {}))

    @httpretty.activate
    def test_get_credential_secret_by_credential_name_return_status_code_200(self):
        """ Test successful get credential secret """
        register_authenticate_url_success()
        register_get_credential_by_filter_success()
        register_get_credential_secret_by_credential_id_success()
        client = VaultOneAPIClient(_API_BASE_URL)
        client.headers = {
            "authorization": "Bearer auth-token",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }
        response = client.get_credential_secret_by_credential_name(
            "Credential Test")
        expected_response = {
            "status": HTTPStatus.OK,
            "data": {
                "username": "username",
                "password": "password",
                "privateKey": ""
            }
        }
        self.assertEqual(HTTPStatus.OK, response.get("status"))
        self.assertDictEqual(expected_response, response)

    @httpretty.activate
    def test_get_credential_secret_by_credential_name_return_status_code_not_200(self):
        """ Test failure get credential secret return not found """
        register_authenticate_url_success()
        register_get_credential_by_filter_return_not_found()
        register_get_credential_secret_by_credential_id_success()
        client = VaultOneAPIClient(_API_BASE_URL)
        client.headers = {
            "authorization": "Bearer auth-token",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }
        response = client.get_credential_secret_by_credential_name(
            "Credential Test")
        expected_response = {
            "status": HTTPStatus.NOT_FOUND,
            "data": None
        }

        self.assertEqual(HTTPStatus.NOT_FOUND, response.get("status"))
        self.assertDictEqual(expected_response, response)

    @httpretty.activate
    def test_get_credential_secret_by_credential_name_return_all_credentials(self):
        """ Test get credential secret return all credentials """
        register_authenticate_url_success()
        register_get_credential_by_filter_all_credentials_success()
        register_get_credential_secret_by_credential_id_success()
        client = VaultOneAPIClient(_API_BASE_URL)

        client.headers = {
            "authorization": "Bearer auth-token",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }
        response = client.get_all_credential_secrets_by_credential_name(
            "Credential Test")
        expected_response = {
            "status": HTTPStatus.MULTI_STATUS,
            "data": [
                {
                    "status": HTTPStatus.OK,
                    "data": {
                        "username": "username",
                        "password": "password",
                        "privateKey": ""
                    }
                },
                {
                    "status": HTTPStatus.OK,
                    "data": {
                        "username": "username",
                        "password": "password",
                        "privateKey": ""
                    }
                }
            ]
        }
        self.assertEqual(HTTPStatus.MULTI_STATUS, response.get("status"))
        self.assertDictEqual(expected_response, response)

    @httpretty.activate
    def test_get_credential_secret_by_credential_name_return_all_credentials_not_found(self):
        """ Test get credential secret return all credentials """
        register_authenticate_url_success()
        register_get_credential_by_filter_all_credentials_success()
        register_get_credential_secret_by_credential_id_failure()
        client = VaultOneAPIClient(_API_BASE_URL)

        client.headers = {
            "authorization": "Bearer auth-token",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }
        response = client.get_all_credential_secrets_by_credential_name(
            "Credential Test")

        expected_response = {
            "status": HTTPStatus.MULTI_STATUS,
            "data": [
                {
                    "data": None,
                    "status": 404
                },
                {
                    "data": None,
                    "status": 404
                }
            ]
        }
        self.assertEqual(HTTPStatus.MULTI_STATUS, response.get("status"))
        self.assertDictEqual(expected_response, response)

    @httpretty.activate
    def test_get_credential_secret_by_credential_name_return_unauthorized(self):
        """ Test get credential secret return unauthorized """

        register_authenticate_url_success()
        register_get_credential_by_filter_unauthorized()
        client = VaultOneAPIClient(_API_BASE_URL)

        client.headers = {
            "authorization": "Bearer auth-token",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }

        response = client.get_credential_secret_by_credential_name(
            "Credential Test")
        expected_response = {
            "status": HTTPStatus.UNAUTHORIZED,
            "data": None
        }

        self.assertEqual(HTTPStatus.UNAUTHORIZED, response.get("status"))
        self.assertDictEqual(expected_response, response)

    @httpretty.activate
    def test_get_credential_secret_by_credential_name_all_credentials_return_unauthorized(self):
        """ Test get all credentials return unauthorized """

        register_authenticate_url_success()
        register_get_credential_by_filter_unauthorized()
        client = VaultOneAPIClient(_API_BASE_URL)

        client.headers = {
            "authorization": "Bearer auth-token",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }

        response = client.get_all_credential_secrets_by_credential_name(
            "Credential Test")

        expected_response = {
            "status": HTTPStatus.UNAUTHORIZED,
            "data": None
        }

        self.assertEqual(HTTPStatus.UNAUTHORIZED, response.get("status"))
        self.assertDictEqual(expected_response, response)

    @httpretty.activate
    def test_get_credential_secret_by_credential_name_will_authorize_return_credential(self):
        """ Test get credential secret by name is not authorized at first """

        register_authenticate_url_success()
        register_get_credential_by_filter_success()
        register_get_credential_secret_by_credential_id_success()
        client = VaultOneAPIClient(_API_BASE_URL)

        client.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }

        response = client.get_credential_secret_by_credential_name(
            "Credential Test")

        expected_response = {
            "status": HTTPStatus.OK,
            "data": {
                "username": "username",
                "password": "password",
                "privateKey": ""
            }
        }

        self.assertEqual(HTTPStatus.OK, response.get("status"))
        self.assertDictEqual(expected_response, response)

    @httpretty.activate
    def test_get_all_credential_secrets_by_credential_name_will_authorize(self):
        """ Test get all credential secrets by name is not authorized at first """

        register_authenticate_url_success()
        register_get_credential_by_filter_all_credentials_success()
        register_get_credential_secret_by_credential_id_success()
        client = VaultOneAPIClient(_API_BASE_URL)

        client.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }

        response = client.get_all_credential_secrets_by_credential_name(
            "Credential Test")

        expected_response = {
            "status": HTTPStatus.MULTI_STATUS,
            "data": [
                {
                    "status": HTTPStatus.OK,
                    "data": {
                        "username": "username",
                        "password": "password",
                        "privateKey": ""
                    }
                },
                {
                    "status": HTTPStatus.OK,
                    "data": {
                        "username": "username",
                        "password": "password",
                        "privateKey": ""
                    }
                }
            ]
        }

        self.assertEqual(HTTPStatus.MULTI_STATUS, response.get("status"))
        self.assertDictEqual(expected_response, response)

    @httpretty.activate
    @mock.patch.object(VaultOneAPIClient, "register_credentials_in_manager")
    def test_get_all_credential_secrets_by_credential_name_cached_credential(self, mock_parameter):
        """ Test get all credential secrets by credential name
            validate cached credential
        """

        register_authenticate_url_success()
        register_get_credential_by_filter_all_credentials_success()
        register_get_credential_secret_by_credential_id_success()

        client = VaultOneAPIClient(_API_BASE_URL)

        client.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }

        response = client.get_all_credential_secrets_by_credential_name(
            "Credential Test")

        response = client.get_all_credential_secrets_by_credential_name(
            "Credential Test")

        expected_response = {
            "status": HTTPStatus.MULTI_STATUS,
            "data": [
                {
                    "status": HTTPStatus.OK,
                    "data": {
                        "username": "username",
                        "password": "password",
                        "privateKey": ""
                    }
                },
                {
                    "status": HTTPStatus.OK,
                    "data": {
                        "username": "username",
                        "password": "password",
                        "privateKey": ""
                    }
                }
            ]
        }

        self.assertEqual(2, mock_parameter.call_count)
        self.assertEqual(HTTPStatus.MULTI_STATUS, response.get("status"))
        self.assertDictEqual(expected_response, response)


if __name__ == "__main__":
    unittest.main(failfast=True)
