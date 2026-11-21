from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx2

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.event_list import EventList
from ...models.problem import Problem
from ...types import UNSET, Unset
from typing import cast



def _get_kwargs(
    *,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> dict[str, Any]:
    

    

    params: dict[str, Any] = {}

    params["limit"] = limit

    params["cursor"] = cursor


    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}


    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/v1/events",
        "params": params,
    }


    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> EventList | Problem | None:
    if response.status_code == 200:
        response_200 = EventList.from_dict(response.json())



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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Response[EventList | Problem]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> Response[EventList | Problem]:
    """ Read the event feed

     Events for this workspace, oldest first, kept 30 days. Start without a
    cursor, then pass each `next_cursor`. At the end of the feed
    `next_cursor` is the position to poll from next, not `null`: when no
    event follows the cursor you sent, it is that same cursor. If the
    feed was rebuilt, an old cursor answers `feed_reset`.

    Event types use `resource.verb_past` names, for example `key.created`,
    `key.revoked`, `usage.limit_reached`, `account.suspended`. New types
    may be added within `/v1`; ignore types you do not know.

    Scopes: `events:read`.

    Args:
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EventList | Problem]
     """


    kwargs = _get_kwargs(
        limit=limit,
cursor=cursor,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> EventList | Problem | None:
    """ Read the event feed

     Events for this workspace, oldest first, kept 30 days. Start without a
    cursor, then pass each `next_cursor`. At the end of the feed
    `next_cursor` is the position to poll from next, not `null`: when no
    event follows the cursor you sent, it is that same cursor. If the
    feed was rebuilt, an old cursor answers `feed_reset`.

    Event types use `resource.verb_past` names, for example `key.created`,
    `key.revoked`, `usage.limit_reached`, `account.suspended`. New types
    may be added within `/v1`; ignore types you do not know.

    Scopes: `events:read`.

    Args:
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EventList | Problem
     """


    return sync_detailed(
        client=client,
limit=limit,
cursor=cursor,

    ).parsed

async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> Response[EventList | Problem]:
    """ Read the event feed

     Events for this workspace, oldest first, kept 30 days. Start without a
    cursor, then pass each `next_cursor`. At the end of the feed
    `next_cursor` is the position to poll from next, not `null`: when no
    event follows the cursor you sent, it is that same cursor. If the
    feed was rebuilt, an old cursor answers `feed_reset`.

    Event types use `resource.verb_past` names, for example `key.created`,
    `key.revoked`, `usage.limit_reached`, `account.suspended`. New types
    may be added within `/v1`; ignore types you do not know.

    Scopes: `events:read`.

    Args:
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EventList | Problem]
     """


    kwargs = _get_kwargs(
        limit=limit,
cursor=cursor,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> EventList | Problem | None:
    """ Read the event feed

     Events for this workspace, oldest first, kept 30 days. Start without a
    cursor, then pass each `next_cursor`. At the end of the feed
    `next_cursor` is the position to poll from next, not `null`: when no
    event follows the cursor you sent, it is that same cursor. If the
    feed was rebuilt, an old cursor answers `feed_reset`.

    Event types use `resource.verb_past` names, for example `key.created`,
    `key.revoked`, `usage.limit_reached`, `account.suspended`. New types
    may be added within `/v1`; ignore types you do not know.

    Scopes: `events:read`.

    Args:
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EventList | Problem
     """


    return (await asyncio_detailed(
        client=client,
limit=limit,
cursor=cursor,

    )).parsed
