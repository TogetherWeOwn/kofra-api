# API token not found

Code: `token_not_found`
HTTP status: 404
Retryable: no, not without a change

No API token with this ID exists in the workspace that you can manage, or it has been revoked.

## What to do

List your API tokens with GET /v1/tokens and use one of the returned IDs.

## Example

```http
HTTP/1.1 404
Content-Type: application/problem+json
Kofra-Request-Id: req_01jd3examplerequestid0000
```

```json
{
  "type": "https://kofra.app/docs/errors/token_not_found",
  "title": "API token not found",
  "status": 404,
  "code": "token_not_found",
  "detail": "No API token \"tok_01jd3p5d9v1n6z8r0t2v4x6y8a\" exists.",
  "hint": "List your API tokens with GET /v1/tokens and use one of the returned IDs.",
  "docs_url": "https://kofra.app/docs/errors/token_not_found.md",
  "request_id": "req_01jd3examplerequestid0000",
  "retryable": false
}
```

The `code` field is stable within `/v1`; `title` and `detail` may be reworded.
