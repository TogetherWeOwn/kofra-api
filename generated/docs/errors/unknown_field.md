# Request has a field the API does not know

Code: `unknown_field`
HTTP status: 400
Retryable: no, not without a change

The request body has a field that the operation does not accept. Unknown fields are refused so that a misspelt field never silently does nothing.

## What to do

Remove or correct the field named by `errors[].pointer`; the API reference lists the accepted fields.

## Example

```http
HTTP/1.1 400
Content-Type: application/problem+json
Kofra-Request-Id: req_01jd3examplerequestid0000
```

```json
{
  "type": "https://kofra.app/docs/errors/unknown_field",
  "title": "Request has a field the API does not know",
  "status": 400,
  "code": "unknown_field",
  "detail": "The field \"/nmae\" is not accepted by this operation.",
  "hint": "Remove or correct the field named by `errors[].pointer`; the API reference lists the accepted fields.",
  "docs_url": "https://kofra.app/docs/errors/unknown_field.md",
  "request_id": "req_01jd3examplerequestid0000",
  "retryable": false
}
```

The `code` field is stable within `/v1`; `title` and `detail` may be reworded.
