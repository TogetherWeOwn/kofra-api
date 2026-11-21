from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx2

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.object_list import ObjectList
from ...models.objects_list_delimiter import ObjectsListDelimiter
from ...models.problem import Problem
from ...types import UNSET, Unset
from typing import cast



def _get_kwargs(
    bucket: str,
    *,
    prefix: str | Unset = UNSET,
    delimiter: ObjectsListDelimiter | Unset = UNSET,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> dict[str, Any]:
    

    

    params: dict[str, Any] = {}

    params["prefix"] = prefix

    json_delimiter: str | Unset = UNSET
    if not isinstance(delimiter, Unset):
        json_delimiter = delimiter.value

    params["delimiter"] = json_delimiter

    params["limit"] = limit

    params["cursor"] = cursor


    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}


    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/v1/buckets/{bucket}/objects".format(bucket=quote(str(bucket), safe=""),),
        "params": params,
    }


    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> ObjectList | Problem | None:
    if response.status_code == 200:
        response_200 = ObjectList.from_dict(response.json())



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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx2.Response) -> Response[ObjectList | Problem]:
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
    prefix: str | Unset = UNSET,
    delimiter: ObjectsListDelimiter | Unset = UNSET,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> Response[ObjectList | Problem]:
    """ List objects

     Lists the objects in a bucket in key order (UTF-8 byte order). With
    `delimiter=/`, keys that continue past the next `/` after `prefix` are
    rolled up into `prefixes`, as folders. Each page holds at most `limit`
    entries in `data` and `prefixes` together. Object data is read through
    the S3 endpoint or a presigned URL, never through this API.

    Scopes: `objects:read`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.
        prefix (str | Unset):
        delimiter (ObjectsListDelimiter | Unset):
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ObjectList | Problem]
     """


    kwargs = _get_kwargs(
        bucket=bucket,
prefix=prefix,
delimiter=delimiter,
limit=limit,
cursor=cursor,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    bucket: str,
    *,
    client: AuthenticatedClient,
    prefix: str | Unset = UNSET,
    delimiter: ObjectsListDelimiter | Unset = UNSET,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> ObjectList | Problem | None:
    """ List objects

     Lists the objects in a bucket in key order (UTF-8 byte order). With
    `delimiter=/`, keys that continue past the next `/` after `prefix` are
    rolled up into `prefixes`, as folders. Each page holds at most `limit`
    entries in `data` and `prefixes` together. Object data is read through
    the S3 endpoint or a presigned URL, never through this API.

    Scopes: `objects:read`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.
        prefix (str | Unset):
        delimiter (ObjectsListDelimiter | Unset):
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ObjectList | Problem
     """


    return sync_detailed(
        bucket=bucket,
client=client,
prefix=prefix,
delimiter=delimiter,
limit=limit,
cursor=cursor,

    ).parsed

async def asyncio_detailed(
    bucket: str,
    *,
    client: AuthenticatedClient,
    prefix: str | Unset = UNSET,
    delimiter: ObjectsListDelimiter | Unset = UNSET,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> Response[ObjectList | Problem]:
    """ List objects

     Lists the objects in a bucket in key order (UTF-8 byte order). With
    `delimiter=/`, keys that continue past the next `/` after `prefix` are
    rolled up into `prefixes`, as folders. Each page holds at most `limit`
    entries in `data` and `prefixes` together. Object data is read through
    the S3 endpoint or a presigned URL, never through this API.

    Scopes: `objects:read`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.
        prefix (str | Unset):
        delimiter (ObjectsListDelimiter | Unset):
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ObjectList | Problem]
     """


    kwargs = _get_kwargs(
        bucket=bucket,
prefix=prefix,
delimiter=delimiter,
limit=limit,
cursor=cursor,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    bucket: str,
    *,
    client: AuthenticatedClient,
    prefix: str | Unset = UNSET,
    delimiter: ObjectsListDelimiter | Unset = UNSET,
    limit: int | Unset = 50,
    cursor: str | Unset = UNSET,

) -> ObjectList | Problem | None:
    """ List objects

     Lists the objects in a bucket in key order (UTF-8 byte order). With
    `delimiter=/`, keys that continue past the next `/` after `prefix` are
    rolled up into `prefixes`, as folders. Each page holds at most `limit`
    entries in `data` and `prefixes` together. Object data is read through
    the S3 endpoint or a presigned URL, never through this API.

    Scopes: `objects:read`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.
        prefix (str | Unset):
        delimiter (ObjectsListDelimiter | Unset):
        limit (int | Unset):  Default: 50.
        cursor (str | Unset): An opaque position in a list. Pass it back unchanged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ObjectList | Problem
     """


    return (await asyncio_detailed(
        bucket=bucket,
client=client,
prefix=prefix,
delimiter=delimiter,
limit=limit,
cursor=cursor,

    )).parsed
