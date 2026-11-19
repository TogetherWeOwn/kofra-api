from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx2

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.bucket import Bucket
from ...models.bucket_create import BucketCreate
from ...models.problem import Problem
from ...types import UNSET, Unset
from typing import cast



def _get_kwargs(
    *,
    body: BucketCreate,
    idempotency_key: str | Unset = UNSET,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(idempotency_key, Unset):
        headers["Idempotency-Key"] = idempotency_key



    

    

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/buckets",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Bucket | Problem | None:
    if response.status_code == 201:
        response_201 = Bucket.from_dict(response.json())



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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Response[Bucket | Problem]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: BucketCreate,
    idempotency_key: str | Unset = UNSET,

) -> Response[Bucket | Problem]:
    """ Create a bucket

     Creates an empty bucket. Bucket names are unique within the workspace.

    Scopes: `buckets:write`.

    Args:
        idempotency_key (str | Unset):
        body (BucketCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Bucket | Problem]
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
    body: BucketCreate,
    idempotency_key: str | Unset = UNSET,

) -> Bucket | Problem | None:
    """ Create a bucket

     Creates an empty bucket. Bucket names are unique within the workspace.

    Scopes: `buckets:write`.

    Args:
        idempotency_key (str | Unset):
        body (BucketCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Bucket | Problem
     """


    return sync_detailed(
        client=client,
body=body,
idempotency_key=idempotency_key,

    ).parsed

async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: BucketCreate,
    idempotency_key: str | Unset = UNSET,

) -> Response[Bucket | Problem]:
    """ Create a bucket

     Creates an empty bucket. Bucket names are unique within the workspace.

    Scopes: `buckets:write`.

    Args:
        idempotency_key (str | Unset):
        body (BucketCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Bucket | Problem]
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
    body: BucketCreate,
    idempotency_key: str | Unset = UNSET,

) -> Bucket | Problem | None:
    """ Create a bucket

     Creates an empty bucket. Bucket names are unique within the workspace.

    Scopes: `buckets:write`.

    Args:
        idempotency_key (str | Unset):
        body (BucketCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Bucket | Problem
     """


    return (await asyncio_detailed(
        client=client,
body=body,
idempotency_key=idempotency_key,

    )).parsed
