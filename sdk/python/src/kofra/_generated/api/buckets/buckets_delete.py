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
    bucket: str,
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
        "url": "/v1/buckets/{bucket}".format(bucket=quote(str(bucket), safe=""),),
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
    bucket: str,
    *,
    client: AuthenticatedClient,
    dry_run: bool | Unset = False,
    idempotency_key: str | Unset = UNSET,

) -> Response[Any | Plan | Problem]:
    """ Delete a bucket

     Deletes an empty bucket and every access key grant on it. A bucket that
    still holds objects is refused with `bucket_not_empty`; delete the
    objects through the S3 endpoint first. Deletion is final, so it is
    done in the console: a request with an API token is refused with
    `confirmation_required`. A dry run needs no confirmation.

    Scopes: `buckets:delete`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.
        dry_run (bool | Unset):  Default: False.
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Plan | Problem]
     """


    kwargs = _get_kwargs(
        bucket=bucket,
dry_run=dry_run,
idempotency_key=idempotency_key,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    bucket: str,
    *,
    client: AuthenticatedClient,
    dry_run: bool | Unset = False,
    idempotency_key: str | Unset = UNSET,

) -> Any | Plan | Problem | None:
    """ Delete a bucket

     Deletes an empty bucket and every access key grant on it. A bucket that
    still holds objects is refused with `bucket_not_empty`; delete the
    objects through the S3 endpoint first. Deletion is final, so it is
    done in the console: a request with an API token is refused with
    `confirmation_required`. A dry run needs no confirmation.

    Scopes: `buckets:delete`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.
        dry_run (bool | Unset):  Default: False.
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Plan | Problem
     """


    return sync_detailed(
        bucket=bucket,
client=client,
dry_run=dry_run,
idempotency_key=idempotency_key,

    ).parsed

async def asyncio_detailed(
    bucket: str,
    *,
    client: AuthenticatedClient,
    dry_run: bool | Unset = False,
    idempotency_key: str | Unset = UNSET,

) -> Response[Any | Plan | Problem]:
    """ Delete a bucket

     Deletes an empty bucket and every access key grant on it. A bucket that
    still holds objects is refused with `bucket_not_empty`; delete the
    objects through the S3 endpoint first. Deletion is final, so it is
    done in the console: a request with an API token is refused with
    `confirmation_required`. A dry run needs no confirmation.

    Scopes: `buckets:delete`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.
        dry_run (bool | Unset):  Default: False.
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Plan | Problem]
     """


    kwargs = _get_kwargs(
        bucket=bucket,
dry_run=dry_run,
idempotency_key=idempotency_key,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    bucket: str,
    *,
    client: AuthenticatedClient,
    dry_run: bool | Unset = False,
    idempotency_key: str | Unset = UNSET,

) -> Any | Plan | Problem | None:
    """ Delete a bucket

     Deletes an empty bucket and every access key grant on it. A bucket that
    still holds objects is refused with `bucket_not_empty`; delete the
    objects through the S3 endpoint first. Deletion is final, so it is
    done in the console: a request with an API token is refused with
    `confirmation_required`. A dry run needs no confirmation.

    Scopes: `buckets:delete`.

    Args:
        bucket (str): 3 to 63 lowercase letters, digits or hyphens; starts and ends with a letter
            or digit.
        dry_run (bool | Unset):  Default: False.
        idempotency_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx2.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Plan | Problem
     """


    return (await asyncio_detailed(
        bucket=bucket,
client=client,
dry_run=dry_run,
idempotency_key=idempotency_key,

    )).parsed
