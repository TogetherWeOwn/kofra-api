# Too many uploads in progress

Code: `upload_limit_reached`
HTTP status: 409
Retryable: no, not without a change

The workspace has as many uploads in progress as it may have at once; the usage answer shows the limit (`open_uploads`).

## What to do

Complete or abort an upload in progress, then start the new one.

## Example

```http
HTTP/1.1 409
Content-Type: application/problem+json
Kofra-Request-Id: req_01jd3examplerequestid0000
```

```json
{
  "type": "https://kofra.app/docs/errors/upload_limit_reached",
  "title": "Too many uploads in progress",
  "status": 409,
  "code": "upload_limit_reached",
  "detail": "The workspace already has the most uploads in progress it may have.",
  "hint": "Complete or abort an upload in progress, then start the new one.",
  "docs_url": "https://kofra.app/docs/errors/upload_limit_reached.md",
  "request_id": "req_01jd3examplerequestid0000",
  "retryable": false
}
```

The `code` field is stable within `/v1`; `title` and `detail` may be reworded.
