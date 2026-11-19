from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx2

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.problem import Problem
from ...models.usage_day_list import UsageDayList
from ...types import UNSET, Unset
from typing import cast
import datetime



def _get_kwargs(
    *,
    after: datetime.date | Unset = UNSET,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> dict[str, Any]:
    

    

    params: dict[str, Any] = {}

    json_after: str | Unset = UNSET
    if not isinstance(after, Unset):
        json_after = after.isoformat()
    params["after"] = json_after

    params["limit"] = limit

    params["cursor"] = cursor


    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}


    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/v1/usage/days",
        "params": params,
    }


    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Problem | UsageDayList | None:
    if response.status_code == 200:
        response_200 = UsageDayList.from_dict(response.json())



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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Response[Problem | UsageDayList]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    after: datetime.date | Unset = UNSET,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> Response[Problem | UsageDayList]:
    """ List daily usage

     One row per UTC day, oldest first, kept 400 days. A `provisional` day
    can still change; a `final` day is sealed; an `under_review` day is
    being re-checked and may be corrected.

    Scopes: `usage:read`.

    Args:
        after (datetime.date | Unset):
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Problem | UsageDayList]
     """


    kwargs = _get_kwargs(
        after=after,
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
    after: datetime.date | Unset = UNSET,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> Problem | UsageDayList | None:
    """ List daily usage

     One row per UTC day, oldest first, kept 400 days. A `provisional` day
    can still change; a `final` day is sealed; an `under_review` day is
    being re-checked and may be corrected.

    Scopes: `usage:read`.

    Args:
        after (datetime.date | Unset):
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Problem | UsageDayList
     """


    return sync_detailed(
        client=client,
after=after,
limit=limit,
cursor=cursor,

    ).parsed

async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    after: datetime.date | Unset = UNSET,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> Response[Problem | UsageDayList]:
    """ List daily usage

     One row per UTC day, oldest first, kept 400 days. A `provisional` day
    can still change; a `final` day is sealed; an `under_review` day is
    being re-checked and may be corrected.

    Scopes: `usage:read`.

    Args:
        after (datetime.date | Unset):
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Problem | UsageDayList]
     """


    kwargs = _get_kwargs(
        after=after,
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
    after: datetime.date | Unset = UNSET,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> Problem | UsageDayList | None:
    """ List daily usage

     One row per UTC day, oldest first, kept 400 days. A `provisional` day
    can still change; a `final` day is sealed; an `under_review` day is
    being re-checked and may be corrected.

    Scopes: `usage:read`.

    Args:
        after (datetime.date | Unset):
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Problem | UsageDayList
     """


    return (await asyncio_detailed(
        client=client,
after=after,
limit=limit,
cursor=cursor,

    )).parsed
