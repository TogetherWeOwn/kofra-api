from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx2

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.api_token_create import ApiTokenCreate
from ...models.api_token_created import ApiTokenCreated
from ...models.problem import Problem
from ...types import UNSET, Unset
from typing import cast



def _get_kwargs(
    *,
    body: ApiTokenCreate,
    idempotency_key: str | Unset = UNSET,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(idempotency_key, Unset):
        headers["Idempotency-Key"] = idempotency_key



    

    

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/tokens",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> ApiTokenCreated | Problem | None:
    if response.status_code == 201:
        response_201 = ApiTokenCreated.from_dict(response.json())



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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Response[ApiTokenCreated | Problem]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: ApiTokenCreate,
    idempotency_key: str | Unset = UNSET,

) -> Response[ApiTokenCreated | Problem]:
    """ Create an API token

     Creates an API token for the member who makes the request. The token
    is in this response only; store it at once. A replay of the same
    request with the same `Idempotency-Key` returns the token with
    `token: null`: revoke that token and create a new one if it was lost.

    A token can never hold more than the credential that creates it: every
    scope must be one the caller holds (`insufficient_scope` otherwise),
    a bucket list must lie inside the caller's (`bucket_not_allowed`), an
    address list inside the caller's (`ip_not_allowed`), and the expiry
    must not be later than the caller's (without `expires_in_days`, the
    token gets 90 days or the caller's remaining life, whichever is
    shorter). A token marked `agent` cannot create or revoke tokens, and
    cannot be given `tokens:write`. The token's permission is also limited
    by the member's role at every request.

    Scopes: `tokens:write`.

    Args:
        idempotency_key (str | Unset):
        body (ApiTokenCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ApiTokenCreated | Problem]
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
    body: ApiTokenCreate,
    idempotency_key: str | Unset = UNSET,

) -> ApiTokenCreated | Problem | None:
    """ Create an API token

     Creates an API token for the member who makes the request. The token
    is in this response only; store it at once. A replay of the same
    request with the same `Idempotency-Key` returns the token with
    `token: null`: revoke that token and create a new one if it was lost.

    A token can never hold more than the credential that creates it: every
    scope must be one the caller holds (`insufficient_scope` otherwise),
    a bucket list must lie inside the caller's (`bucket_not_allowed`), an
    address list inside the caller's (`ip_not_allowed`), and the expiry
    must not be later than the caller's (without `expires_in_days`, the
    token gets 90 days or the caller's remaining life, whichever is
    shorter). A token marked `agent` cannot create or revoke tokens, and
    cannot be given `tokens:write`. The token's permission is also limited
    by the member's role at every request.

    Scopes: `tokens:write`.

    Args:
        idempotency_key (str | Unset):
        body (ApiTokenCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ApiTokenCreated | Problem
     """


    return sync_detailed(
        client=client,
body=body,
idempotency_key=idempotency_key,

    ).parsed

async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ApiTokenCreate,
    idempotency_key: str | Unset = UNSET,

) -> Response[ApiTokenCreated | Problem]:
    """ Create an API token

     Creates an API token for the member who makes the request. The token
    is in this response only; store it at once. A replay of the same
    request with the same `Idempotency-Key` returns the token with
    `token: null`: revoke that token and create a new one if it was lost.

    A token can never hold more than the credential that creates it: every
    scope must be one the caller holds (`insufficient_scope` otherwise),
    a bucket list must lie inside the caller's (`bucket_not_allowed`), an
    address list inside the caller's (`ip_not_allowed`), and the expiry
    must not be later than the caller's (without `expires_in_days`, the
    token gets 90 days or the caller's remaining life, whichever is
    shorter). A token marked `agent` cannot create or revoke tokens, and
    cannot be given `tokens:write`. The token's permission is also limited
    by the member's role at every request.

    Scopes: `tokens:write`.

    Args:
        idempotency_key (str | Unset):
        body (ApiTokenCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ApiTokenCreated | Problem]
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
    body: ApiTokenCreate,
    idempotency_key: str | Unset = UNSET,

) -> ApiTokenCreated | Problem | None:
    """ Create an API token

     Creates an API token for the member who makes the request. The token
    is in this response only; store it at once. A replay of the same
    request with the same `Idempotency-Key` returns the token with
    `token: null`: revoke that token and create a new one if it was lost.

    A token can never hold more than the credential that creates it: every
    scope must be one the caller holds (`insufficient_scope` otherwise),
    a bucket list must lie inside the caller's (`bucket_not_allowed`), an
    address list inside the caller's (`ip_not_allowed`), and the expiry
    must not be later than the caller's (without `expires_in_days`, the
    token gets 90 days or the caller's remaining life, whichever is
    shorter). A token marked `agent` cannot create or revoke tokens, and
    cannot be given `tokens:write`. The token's permission is also limited
    by the member's role at every request.

    Scopes: `tokens:write`.

    Args:
        idempotency_key (str | Unset):
        body (ApiTokenCreate):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ApiTokenCreated | Problem
     """


    return (await asyncio_detailed(
        client=client,
body=body,
idempotency_key=idempotency_key,

    )).parsed
