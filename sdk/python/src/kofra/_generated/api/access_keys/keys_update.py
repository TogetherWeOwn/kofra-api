from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx2

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.access_key import AccessKey
from ...models.access_key_update import AccessKeyUpdate
from ...models.problem import Problem
from ...types import UNSET, Unset
from typing import cast



def _get_kwargs(
    key_id: str,
    *,
    body: AccessKeyUpdate,
    idempotency_key: str | Unset = UNSET,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(idempotency_key, Unset):
        headers["Idempotency-Key"] = idempotency_key



    

    

    _kwargs: dict[str, Any] = {
        "method": "patch",
        "url": "/v1/keys/{key_id}".format(key_id=quote(str(key_id), safe=""),),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> AccessKey | Problem | None:
    if response.status_code == 200:
        response_200 = AccessKey.from_dict(response.json())



        return response_200

    if response.status_code == 400:
        response_400 = Problem.from_dict(response.json())



        return response_400

    if response.status_code == 401:
        response_401 = Problem.from_dict(response.json())



        return response_401

    if response.status_code == 403:
        response_403 = Problem.from_dict(response.json())



        return response_403

    if response.status_code == 404:
        response_404 = Problem.from_dict(response.json())



        return response_404

    if response.status_code == 409:
        response_409 = Problem.from_dict(response.json())



        return response_409

    if response.status_code == 413:
        response_413 = Problem.from_dict(response.json())



        return response_413

    if response.status_code == 415:
        response_415 = Problem.from_dict(response.json())



        return response_415

    if response.status_code == 422:
        response_422 = Problem.from_dict(response.json())



        return response_422

    if response.status_code == 429:
        response_429 = Problem.from_dict(response.json())



        return response_429

    if response.status_code == 500:
        response_500 = Problem.from_dict(response.json())



        return response_500

    if response.status_code == 503:
        response_503 = Problem.from_dict(response.json())



        return response_503

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Response[AccessKey | Problem]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: AccessKeyUpdate,
    idempotency_key: str | Unset = UNSET,

) -> Response[AccessKey | Problem]:
    """ Update an access key

     Renames a key, or adds or widens its grants. A grant is never narrowed
    (`read_write` to `read`) or removed: create a new key with the narrower
    access and revoke this one. Grants not listed are left as they are.

    Scopes: `keys:write`.

    Args:
        key_id (str): The S3 access key ID.
        idempotency_key (str | Unset):
        body (AccessKeyUpdate): At least one of `name` and `grants`. An empty `grants` list is
            refused; leave `grants` out to keep the grants as they are.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AccessKey | Problem]
     """


    kwargs = _get_kwargs(
        key_id=key_id,
body=body,
idempotency_key=idempotency_key,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: AccessKeyUpdate,
    idempotency_key: str | Unset = UNSET,

) -> AccessKey | Problem | None:
    """ Update an access key

     Renames a key, or adds or widens its grants. A grant is never narrowed
    (`read_write` to `read`) or removed: create a new key with the narrower
    access and revoke this one. Grants not listed are left as they are.

    Scopes: `keys:write`.

    Args:
        key_id (str): The S3 access key ID.
        idempotency_key (str | Unset):
        body (AccessKeyUpdate): At least one of `name` and `grants`. An empty `grants` list is
            refused; leave `grants` out to keep the grants as they are.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AccessKey | Problem
     """


    return sync_detailed(
        key_id=key_id,
client=client,
body=body,
idempotency_key=idempotency_key,

    ).parsed

async def asyncio_detailed(
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: AccessKeyUpdate,
    idempotency_key: str | Unset = UNSET,

) -> Response[AccessKey | Problem]:
    """ Update an access key

     Renames a key, or adds or widens its grants. A grant is never narrowed
    (`read_write` to `read`) or removed: create a new key with the narrower
    access and revoke this one. Grants not listed are left as they are.

    Scopes: `keys:write`.

    Args:
        key_id (str): The S3 access key ID.
        idempotency_key (str | Unset):
        body (AccessKeyUpdate): At least one of `name` and `grants`. An empty `grants` list is
            refused; leave `grants` out to keep the grants as they are.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AccessKey | Problem]
     """


    kwargs = _get_kwargs(
        key_id=key_id,
body=body,
idempotency_key=idempotency_key,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: AccessKeyUpdate,
    idempotency_key: str | Unset = UNSET,

) -> AccessKey | Problem | None:
    """ Update an access key

     Renames a key, or adds or widens its grants. A grant is never narrowed
    (`read_write` to `read`) or removed: create a new key with the narrower
    access and revoke this one. Grants not listed are left as they are.

    Scopes: `keys:write`.

    Args:
        key_id (str): The S3 access key ID.
        idempotency_key (str | Unset):
        body (AccessKeyUpdate): At least one of `name` and `grants`. An empty `grants` list is
            refused; leave `grants` out to keep the grants as they are.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AccessKey | Problem
     """


    return (await asyncio_detailed(
        key_id=key_id,
client=client,
body=body,
idempotency_key=idempotency_key,

    )).parsed
