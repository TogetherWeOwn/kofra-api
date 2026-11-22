from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx2

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.account import Account
from ...models.problem import Problem
from ...types import UNSET, Unset
from typing import cast



def _get_kwargs(
    *,
    idempotency_key: str | Unset = UNSET,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(idempotency_key, Unset):
        headers["Idempotency-Key"] = idempotency_key



    

    

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/account/deletion/cancel",
    }


    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Account | Problem | None:
    if response.status_code == 200:
        response_200 = Account.from_dict(response.json())



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

    if response.status_code == 409:
        response_409 = Problem.from_dict(response.json())



        return response_409

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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Response[Account | Problem]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    idempotency_key: str | Unset = UNSET,

) -> Response[Account | Problem]:
    """ Cancel a deletion

     Cancels a deletion that is waiting for confirmation or scheduled, as
    long as `erase_at` has not passed. The account, its buckets and its keys
    work again at once. A deletion request that is still waiting for
    confirmation is cancelled by any request. A scheduled deletion is
    cancelled only on the console's confirmation page; any other request
    is refused with `confirmation_required`.

    Scopes: `account:delete`.

    Args:
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Account | Problem]
     """


    kwargs = _get_kwargs(
        idempotency_key=idempotency_key,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    *,
    client: AuthenticatedClient,
    idempotency_key: str | Unset = UNSET,

) -> Account | Problem | None:
    """ Cancel a deletion

     Cancels a deletion that is waiting for confirmation or scheduled, as
    long as `erase_at` has not passed. The account, its buckets and its keys
    work again at once. A deletion request that is still waiting for
    confirmation is cancelled by any request. A scheduled deletion is
    cancelled only on the console's confirmation page; any other request
    is refused with `confirmation_required`.

    Scopes: `account:delete`.

    Args:
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Account | Problem
     """


    return sync_detailed(
        client=client,
idempotency_key=idempotency_key,

    ).parsed

async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    idempotency_key: str | Unset = UNSET,

) -> Response[Account | Problem]:
    """ Cancel a deletion

     Cancels a deletion that is waiting for confirmation or scheduled, as
    long as `erase_at` has not passed. The account, its buckets and its keys
    work again at once. A deletion request that is still waiting for
    confirmation is cancelled by any request. A scheduled deletion is
    cancelled only on the console's confirmation page; any other request
    is refused with `confirmation_required`.

    Scopes: `account:delete`.

    Args:
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Account | Problem]
     """


    kwargs = _get_kwargs(
        idempotency_key=idempotency_key,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    *,
    client: AuthenticatedClient,
    idempotency_key: str | Unset = UNSET,

) -> Account | Problem | None:
    """ Cancel a deletion

     Cancels a deletion that is waiting for confirmation or scheduled, as
    long as `erase_at` has not passed. The account, its buckets and its keys
    work again at once. A deletion request that is still waiting for
    confirmation is cancelled by any request. A scheduled deletion is
    cancelled only on the console's confirmation page; any other request
    is refused with `confirmation_required`.

    Scopes: `account:delete`.

    Args:
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Account | Problem
     """


    return (await asyncio_detailed(
        client=client,
idempotency_key=idempotency_key,

    )).parsed
