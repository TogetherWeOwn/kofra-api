from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx2

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.plan import Plan
from ...models.problem import Problem
from ...types import UNSET, Unset
from typing import cast



def _get_kwargs(
    token_id: str,
    *,
    dry_run: bool | Unset = False,
    idempotency_key: str | Unset = UNSET,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(idempotency_key, Unset):
        headers["Idempotency-Key"] = idempotency_key



    

    params: dict[str, Any] = {}

    params["dry_run"] = dry_run


    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}


    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/v1/tokens/{token_id}".format(token_id=quote(str(token_id), safe=""),),
        "params": params,
    }


    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Any | Plan | Problem | None:
    if response.status_code == 200:
        response_200 = Plan.from_dict(response.json())



        return response_200

    if response.status_code == 204:
        response_204 = cast(Any, None)
        return response_204

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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Response[Any | Plan | Problem]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    token_id: str,
    *,
    client: AuthenticatedClient,
    dry_run: bool | Unset = False,
    idempotency_key: str | Unset = UNSET,

) -> Response[Any | Plan | Problem]:
    """ Revoke an API token

     Revokes the token at once; requests made with it are refused from then
    on. Members can revoke their own tokens; an Owner or Admin can revoke
    any token of the workspace. Revocation is final; the token disappears
    from the list, so a second revoke answers `token_not_found`.

    Scopes: `tokens:write`.

    Args:
        token_id (str): The API token ID. The token itself is `kofra_tok_`, this ID without
            `tok_`, `_` and the secret.
        dry_run (bool | Unset):  Default: False.
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Plan | Problem]
     """


    kwargs = _get_kwargs(
        token_id=token_id,
dry_run=dry_run,
idempotency_key=idempotency_key,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    token_id: str,
    *,
    client: AuthenticatedClient,
    dry_run: bool | Unset = False,
    idempotency_key: str | Unset = UNSET,

) -> Any | Plan | Problem | None:
    """ Revoke an API token

     Revokes the token at once; requests made with it are refused from then
    on. Members can revoke their own tokens; an Owner or Admin can revoke
    any token of the workspace. Revocation is final; the token disappears
    from the list, so a second revoke answers `token_not_found`.

    Scopes: `tokens:write`.

    Args:
        token_id (str): The API token ID. The token itself is `kofra_tok_`, this ID without
            `tok_`, `_` and the secret.
        dry_run (bool | Unset):  Default: False.
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Plan | Problem
     """


    return sync_detailed(
        token_id=token_id,
client=client,
dry_run=dry_run,
idempotency_key=idempotency_key,

    ).parsed

async def asyncio_detailed(
    token_id: str,
    *,
    client: AuthenticatedClient,
    dry_run: bool | Unset = False,
    idempotency_key: str | Unset = UNSET,

) -> Response[Any | Plan | Problem]:
    """ Revoke an API token

     Revokes the token at once; requests made with it are refused from then
    on. Members can revoke their own tokens; an Owner or Admin can revoke
    any token of the workspace. Revocation is final; the token disappears
    from the list, so a second revoke answers `token_not_found`.

    Scopes: `tokens:write`.

    Args:
        token_id (str): The API token ID. The token itself is `kofra_tok_`, this ID without
            `tok_`, `_` and the secret.
        dry_run (bool | Unset):  Default: False.
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Plan | Problem]
     """


    kwargs = _get_kwargs(
        token_id=token_id,
dry_run=dry_run,
idempotency_key=idempotency_key,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    token_id: str,
    *,
    client: AuthenticatedClient,
    dry_run: bool | Unset = False,
    idempotency_key: str | Unset = UNSET,

) -> Any | Plan | Problem | None:
    """ Revoke an API token

     Revokes the token at once; requests made with it are refused from then
    on. Members can revoke their own tokens; an Owner or Admin can revoke
    any token of the workspace. Revocation is final; the token disappears
    from the list, so a second revoke answers `token_not_found`.

    Scopes: `tokens:write`.

    Args:
        token_id (str): The API token ID. The token itself is `kofra_tok_`, this ID without
            `tok_`, `_` and the secret.
        dry_run (bool | Unset):  Default: False.
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Plan | Problem
     """


    return (await asyncio_detailed(
        token_id=token_id,
client=client,
dry_run=dry_run,
idempotency_key=idempotency_key,

    )).parsed
