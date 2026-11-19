from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx2

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.access_key_create import AccessKeyCreate
from ...models.access_key_created import AccessKeyCreated
from ...models.problem import Problem
from ...types import UNSET, Unset
from typing import cast



def _get_kwargs(
    *,
    body: AccessKeyCreate,
    idempotency_key: str | Unset = UNSET,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(idempotency_key, Unset):
        headers["Idempotency-Key"] = idempotency_key



    

    

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/keys",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> AccessKeyCreated | Problem | None:
    if response.status_code == 201:
        response_201 = AccessKeyCreated.from_dict(response.json())



        return response_201

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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Response[AccessKeyCreated | Problem]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: AccessKeyCreate,
    idempotency_key: str | Unset = UNSET,

) -> Response[AccessKeyCreated | Problem]:
    """ Create an access key

     Creates an S3 access key pair with access to the listed buckets. The
    secret is in this response only; store it at once. A replay of the same
    request with the same `Idempotency-Key` returns the key with
    `secret_access_key: null`: revoke that key and create a new one if the
    secret was lost.

    Whoever holds a key with access to a bucket can read its objects, so
    `keys:write` is treated as data access.

    Scopes: `keys:write`.

    Args:
        idempotency_key (str | Unset):
        body (AccessKeyCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AccessKeyCreated | Problem]
     """


    kwargs = _get_kwargs(
        body=body,
idempotency_key=idempotency_key,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    *,
    client: AuthenticatedClient,
    body: AccessKeyCreate,
    idempotency_key: str | Unset = UNSET,

) -> AccessKeyCreated | Problem | None:
    """ Create an access key

     Creates an S3 access key pair with access to the listed buckets. The
    secret is in this response only; store it at once. A replay of the same
    request with the same `Idempotency-Key` returns the key with
    `secret_access_key: null`: revoke that key and create a new one if the
    secret was lost.

    Whoever holds a key with access to a bucket can read its objects, so
    `keys:write` is treated as data access.

    Scopes: `keys:write`.

    Args:
        idempotency_key (str | Unset):
        body (AccessKeyCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AccessKeyCreated | Problem
     """


    return sync_detailed(
        client=client,
body=body,
idempotency_key=idempotency_key,

    ).parsed

async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: AccessKeyCreate,
    idempotency_key: str | Unset = UNSET,

) -> Response[AccessKeyCreated | Problem]:
    """ Create an access key

     Creates an S3 access key pair with access to the listed buckets. The
    secret is in this response only; store it at once. A replay of the same
    request with the same `Idempotency-Key` returns the key with
    `secret_access_key: null`: revoke that key and create a new one if the
    secret was lost.

    Whoever holds a key with access to a bucket can read its objects, so
    `keys:write` is treated as data access.

    Scopes: `keys:write`.

    Args:
        idempotency_key (str | Unset):
        body (AccessKeyCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AccessKeyCreated | Problem]
     """


    kwargs = _get_kwargs(
        body=body,
idempotency_key=idempotency_key,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    *,
    client: AuthenticatedClient,
    body: AccessKeyCreate,
    idempotency_key: str | Unset = UNSET,

) -> AccessKeyCreated | Problem | None:
    """ Create an access key

     Creates an S3 access key pair with access to the listed buckets. The
    secret is in this response only; store it at once. A replay of the same
    request with the same `Idempotency-Key` returns the key with
    `secret_access_key: null`: revoke that key and create a new one if the
    secret was lost.

    Whoever holds a key with access to a bucket can read its objects, so
    `keys:write` is treated as data access.

    Scopes: `keys:write`.

    Args:
        idempotency_key (str | Unset):
        body (AccessKeyCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AccessKeyCreated | Problem
     """


    return (await asyncio_detailed(
        client=client,
body=body,
idempotency_key=idempotency_key,

    )).parsed
