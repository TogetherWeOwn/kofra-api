from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx2

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.bucket import Bucket
from ...models.problem import Problem
from typing import cast



def _get_kwargs(
    bucket: str,

) -> dict[str, Any]:
    

    

    

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/v1/buckets/{bucket}".format(bucket=quote(str(bucket), safe=""),),
    }


    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Bucket | Problem | None:
    if response.status_code == 200:
        response_200 = Bucket.from_dict(response.json())



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
    bucket: str,
    *,
    client: AuthenticatedClient,

) -> Response[Bucket | Problem]:
    """ Get a bucket

     Returns one bucket with its size.

    Scopes: `buckets:read`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Bucket | Problem]
     """


    kwargs = _get_kwargs(
        bucket=bucket,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    bucket: str,
    *,
    client: AuthenticatedClient,

) -> Bucket | Problem | None:
    """ Get a bucket

     Returns one bucket with its size.

    Scopes: `buckets:read`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Bucket | Problem
     """


    return sync_detailed(
        bucket=bucket,
client=client,

    ).parsed

async def asyncio_detailed(
    bucket: str,
    *,
    client: AuthenticatedClient,

) -> Response[Bucket | Problem]:
    """ Get a bucket

     Returns one bucket with its size.

    Scopes: `buckets:read`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Bucket | Problem]
     """


    kwargs = _get_kwargs(
        bucket=bucket,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    bucket: str,
    *,
    client: AuthenticatedClient,

) -> Bucket | Problem | None:
    """ Get a bucket

     Returns one bucket with its size.

    Scopes: `buckets:read`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Bucket | Problem
     """


    return (await asyncio_detailed(
        bucket=bucket,
client=client,

    )).parsed
