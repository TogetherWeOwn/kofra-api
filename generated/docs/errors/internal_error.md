# Internal error

Code: `internal_error`
HTTP status: 500
Retryable: no, not without a change

The request failed for a reason that is not one of the codes above. No detail of the cause is returned.

## What to do

Retry once later; if it fails again, contact support and quote the `request_id`.

## Example

```http
HTTP/1.1 500
Content-Type: application/problem+json
Kofra-Request-Id: req_01jd3examplerequestid0000
```

```json
{
  "type": "https://kofra.app/docs/errors/internal_error",
  "title": "Internal error",
  "status": 500,
  "code": "internal_error",
  "detail": "The request could not be completed.",
  "hint": "Retry once later; if it fails again, contact support and quote the `request_id`.",
  "docs_url": "https://kofra.app/docs/errors/internal_error.md",
  "request_id": "req_01jd3examplerequestid0000",
  "retryable": false
}
```

The `code` field is stable within `/v1`; `title` and `detail` may be reworded.
