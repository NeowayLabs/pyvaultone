# pyvaultone

[![Build Status](https://travis-ci.com/NeowayLabs/pyvaultone.svg?branch=main)](https://travis-ci.com/NeowayLabs/pyvaultone)

This project is a library to abstract relevant interactions to the VaultOne application API. Relevant interactions are defined as necessary interactions in order for a bot to retrieve credentials that will be used in the crawling process.

You need a valid Vault One credential to use this library. The username and the password must be encoded in base64 format and must be set to the following environment variables: VAULT_ONE_API_USERNAME, VAULT_ONE_API_PASSWORD and VAULT_ONE_API_BASE_URL.

For more information about Vault One, you can check it out here: https://vaultone.com/

These interactions are read-only, thus this library will not implement write operations using the VaultOne API. The necessary API endpoints are the following:
  - Obtaining an access token to the API;
  - Retrieving credentials based on a filter that identifies the credential;
  - Acquiring a credential secret using a credential unique id provided by the VaultOne API.

The API endpoints that are implemented in this first version are the following, and will be referred hereinafter by their corresponding names:
  - POST /api/TokenAuth/Authenticate - Authenticate Request
  - GET /api/services/app/Credentials/GetAllCredentials?Filter= - Get Credentials Request
  - GET /api/services/app/Credentials/GetCredentialSecret?CredentialId= - Get Credential Secret Request

This API Client implementation only returns the relevant information to be used in the other requests, such as the accessToken and the userId.

## Get Credentials Request

This API Client implementation returns the first credential that matches the filter and only returns relevant information to be used in the Get Credential Secret request, such as the credential id. In order to return the first credential, the function `get_credential_by_filter` should be called. 

If the API user wishes to return all the credentials that match a filter, the function `get_all_credentials_by_filter` should be called.

## Get Credential Secret Request

The Get Credential Secret Request must send the "authorization" header with the token obtained from the Authenticate Request. The CredentialId query parameter should be the credential id obtained from the Get Credentials Request.

This API Client implementation returns the username and the password associated with this credential id.

The environment variables VAULT_ONE_API_USERNAME and VAULT_ONE_API_PASSWORD are required and they must be encoded in base64 format to satisfy Git CI/CD variables requirements.

The environment VAULT_ONE_API_BASE_URL is also required, and its the VaultOne URL. It is used for performing the requests in the desired VaultOne client.

## Get Credential Secret by Credential Name

The function `get_credential_secret_by_credential_name` encapsulates the three requests, and returns the credential parameters (username and password) given a credential name. You may call the function `get_all_credential_secrets_by_credential_name` to obtain an array of credentials for this credential name instead of obtaining a single credential.

## Example returns

All of the functions that interact with the API endpoints previously described in this document return an object with 2 (two) fields: `data` and `status`. The `data` field may be an array, an object or `null`, depending on the function called and the response received by the API.

### `authorize`

```json
{
  "status": 200,
  "data": {
    "accessToken": "token",
    "userId": "id"
  }
}
```

```json
{
  "status": 401,
  "data": null
}
```

### `get_credential_by_filter`

```json
{
  "status": 200,
  "data": {
    "id": "id",
    "name": "Credential Name"
  }
}
```

```json
{
  "status": 404,
  "data": null
}
```

```json
{
  "status": 400,
  "data": null
}
```

### `get_all_credentials_by_filter`

```json
{
  "status": 200,
  "data": [
    {
      "id": "id",
      "name": "Credential Name"
    },
    {
      "id": "id-2",
      "name": "Credential Name 2"
    }
  ]
}
```

```json
{
  "status": 404,
  "data": null
}
```

### `get_credential_secret_by_credential_id`

```json
{
  "status": 200,
  "data": {
    "username": "username",
    "password": "password"
  }
}
```

```json
{
  "status": 404,
  "data": null
}
```

```json
{
  "status": 400,
  "data": null
}
```

### `get_credential_secret`

```json
{
  "status": 200,
  "data": {
    "username": "username",
    "password": "password"
  }
}
```

```json
{
  "status": 401,
  "data": null
}
```

```json
{
  "status": 404,
  "data": null
}
```

### `get_all_credential_secrets`

```json
{
  "status": 207,
  "data": [
    {
      "status": 200,
      "data": {
        "username": "username",
        "password": "password"
      }
    },
    {
      "status": 200,
      "data": {
        "username": "username2",
        "password": "password2"
      }
    }
  ]
}
```

```json
{
  "status": 207,
  "data": [
    {
      "status": 404,
      "data": null
    }
  ]
}
```

## Expected return status codes

- 200 OK
- 400 BAD REQUEST
- 404 NOT FOUND
- 401 UNAUTHORIZED
- 403 FORBIDDEN
- 207 MULTI STATUS

## Tests

### For unit tests:

```sh
make check parameters="<filepath>.py <Class>.<Function>"
```
`parameters filepath init after ./tests`

#### Examples

- All tests
  ```sh
  make check
  ```

- File test
  ```sh
  make check parameters="middleware_test.py"
  ```

- Class of file test
  ```sh
  make check parameters="middleware_test.py ProcessRequestTests"
  ```
  
- Function of class of file test:
  ```sh
  make check parameters="middleware_test.py ProcessRequestTests.test_get_proxy"
  ```

### For integration tests:

```sh
make check-integration parameters="<filepath>.py <Class>.<Function>"
```
`parameters filepath init after ./tests`

Same unit tests examples works to integration tests.

## lint

To run pylint in your code run:

    make lint