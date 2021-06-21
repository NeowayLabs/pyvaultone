""" Module for the Vault One API Client """

import os
import base64
from http import HTTPStatus
from urllib.parse import quote
from requests import get, post


def _send_not_success_response(status_code):
    """ Function to be called when the response is not 200 """
    return {
        "status": status_code,
        "data": None
    }


def get_json_login(username, password):
    """ Function to return the login json given a username and password """
    return {
        "usernameOrEmailAddress": username,
        "password": password
    }


def _build_response_credential_filter_one_credential(credential_items, status_code):
    """ Method to build the response if the API user
        chose to return only the first credential
    """
    return {
        "status": status_code,
        "data": {
            "id": credential_items[0]["id"],
            "name": credential_items[0]["name"]
        }
    }


def _build_response_credential_filter_multiple_credentials(credential_items, status_code):
    """ Method to build the response if the API user
        chose to return all the matched credentials
    """
    return {
        "status": status_code,
        "data": [{
            "id": item["id"],
            "name": item["name"]
        } for item in credential_items]
    }


def _get_credential_items_by_filter(name_filter, base_url, headers):

    query_string = f"?Filter={quote(name_filter)}" if len(
        name_filter.strip()) > 0 else ""

    response = get(
        url=f"{base_url}/api/services/app/Credentials/GetAllCredentials{query_string}",
        headers=headers
    )

    if response.status_code != HTTPStatus.OK:
        return None, response.status_code

    response_json = response.json()
    credential_items = response_json.get("result", {}).get("items", [])
    if len(credential_items) < 1:
        return None, HTTPStatus.NOT_FOUND
    return credential_items, response.status_code


class VaultOneAPIClient():
    """ Class that implements methods to communicate with Vault One API """

    credentials_manager = {}

    def __init__(self, base_url):
        """ Constructor to initialize the base url """
        self.base_url = base_url
        self.headers = {}
        self._access_token = ""
        self._decoded_username = base64.b64decode(
            os.environ.get("VAULT_ONE_API_USERNAME")).decode('utf-8').strip()
        self._decoded_password = base64.b64decode(
            os.environ.get("VAULT_ONE_API_PASSWORD")).decode('utf-8').strip()

    def authorize(self, username, password):
        """ Method to perform the authentication request """
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }

        response = post(
            url=f"{self.base_url}/api/TokenAuth/Authenticate",
            json=get_json_login(username, password),
            headers=headers
        )

        if response.status_code != HTTPStatus.OK:
            return _send_not_success_response(response.status_code)

        response_json = response.json()

        self._access_token = response_json.get(
            'result', {}).get('accessToken', '')

        self.headers = {
            "authorization": f"Bearer {self._access_token}",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/"
                          "537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
            "Content-Type": "application/json"
        }

        return {
            "status": response.status_code,
            "data": {
                "accessToken": self._access_token,
                "userId": response_json.get("result", {}).get("userId", "")
            }
        }

    def _is_authorized(self):
        """ Method to determine if the client has an authorization header """
        return hasattr(self, 'headers') and (self.headers is not None and
                                             len(self.headers.get("authorization", "")) > 0)

    def get_credential_by_filter(self, name_filter):
        """ Method to return only the first credential that matches a given filter """

        if not self._is_authorized():
            return _send_not_success_response(HTTPStatus.BAD_REQUEST)

        credential_items, status_code = _get_credential_items_by_filter(
            name_filter, self.base_url, self.headers)

        if credential_items is None:
            return _send_not_success_response(status_code)

        return _build_response_credential_filter_one_credential(credential_items, status_code)

    def get_all_credentials_by_filter(self, name_filter):
        """ Method to return all the credentials that match a given filter """

        if not self._is_authorized():
            return _send_not_success_response(HTTPStatus.BAD_REQUEST)

        credential_items, status_code = _get_credential_items_by_filter(
            name_filter, self.base_url, self.headers)
        if credential_items is None:
            return _send_not_success_response(status_code)

        return _build_response_credential_filter_multiple_credentials(credential_items, status_code)

    def get_credential_secret_by_credential_id(self, credential_id):
        """ Method to return a credential secret given a credential id """

        if not self._is_authorized():
            return _send_not_success_response(HTTPStatus.BAD_REQUEST)

        query_string = f"?CredentialId={credential_id}" if len(
            credential_id.strip()) > 0 else ""

        response = get(
            url=f"{self.base_url}/api/services/app/Credentials/GetCredentialSecret{query_string}",
            headers=self.headers
        )

        if response.status_code != HTTPStatus.OK:
            return _send_not_success_response(response.status_code)

        try:
            response_json = response.json()
            result = response_json["result"]
        except KeyError:
            return _send_not_success_response(HTTPStatus.INTERNAL_SERVER_ERROR)

        username = result.get("username", "")
        password = result.get("pass") if result.get("pass", None) is not None else ""
        key = result.get("privateKey") if result.get("privateKey", None) is not None else ""

        return {
            "status": response.status_code,
            "data": {
                "username": username,
                "password": password,
                "privateKey": key
            }
        }

    def register_credentials_in_manager(self, client_name, credential_secrets, status_code):
        """ Method to add credential data to credential manager """
        self.credentials_manager[client_name] = {
            "status": status_code,
            "data": credential_secrets
        }

    def get_credential_secret_by_credential_name(self, client_name):
        """ Method to return one credential secret based on the client name """

        if not self._is_authorized():
            authorized = self.authorize(
                self._decoded_username, self._decoded_password)
            if authorized.get("status") != HTTPStatus.OK:
                return _send_not_success_response(authorized.get("status"))

        if client_name in self.credentials_manager:
            return self.credentials_manager[client_name]

        credential_found = self.get_credential_by_filter(client_name)

        if credential_found.get("status") == HTTPStatus.UNAUTHORIZED:
            authorized = self.authorize(
                self._decoded_username, self._decoded_password)
            if authorized.get("status") != HTTPStatus.OK:
                return _send_not_success_response(authorized.get("status"))

            credential_found = self.get_credential_by_filter(client_name)

        if credential_found.get("status") != HTTPStatus.OK:
            return _send_not_success_response(credential_found.get("status"))

        credential_secret_by_credential_id = self.get_credential_secret_by_credential_id(
            credential_found.get("data", {}).get("id"))

        self.register_credentials_in_manager(client_name, credential_secret_by_credential_id.get(
            "data"), credential_secret_by_credential_id.get("status"))

        return credential_secret_by_credential_id

    def get_all_credential_secrets_by_credential_name(self, client_name):
        """ Method to return all credential secrets based on the client name """

        if not self._is_authorized():
            authorized = self.authorize(
                self._decoded_username, self._decoded_password)

            if authorized.get("status") != HTTPStatus.OK:
                return _send_not_success_response(authorized.get("status"))

        if client_name in self.credentials_manager:
            return self.credentials_manager[client_name]

        credential_found = self.get_all_credentials_by_filter(client_name)

        if credential_found.get("status") == HTTPStatus.UNAUTHORIZED:
            authorized = self.authorize(
                self._decoded_username, self._decoded_password)
            if authorized.get("status") != HTTPStatus.OK:
                return _send_not_success_response(authorized.get("status"))

            credential_found = self.get_all_credentials_by_filter(client_name)

        if credential_found.get("status") != HTTPStatus.OK:
            return _send_not_success_response(credential_found.get("status"))

        credential_secrets = [self.get_credential_secret_by_credential_id(credential_secret.get(
            "id", "")) for credential_secret in credential_found.get("data", [])]

        self.register_credentials_in_manager(
            client_name, credential_secrets, HTTPStatus.MULTI_STATUS)

        return {
            "status": HTTPStatus.MULTI_STATUS,
            "data": credential_secrets
        }
