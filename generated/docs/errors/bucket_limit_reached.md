# Too many buckets

Code: `bucket_limit_reached`
HTTP status: 409
Retryable: no, not without a change

A workspace can have at most 10,000 buckets, counting buckets that are still being deleted.

## What to do

Delete a bucket you no longer use, then create the new one.

## Example

```http
HTTP/1.1 409
Content-Type: application/problem+json
Kofra-Request-Id: req_01jd3examplerequestid0000
```

```json
{
  "type": "https://kofra.app/docs/errors/bucket_limit_reached",
  "title": "Too many buckets",
  "status": 409,
  "code": "bucket_limit_reached",
  "detail": "The workspace already has 10,000 buckets.",
  "hint": "Delete a bucket you no longer use, then create the new one.",
  "docs_url": "https://kofra.app/docs/errors/bucket_limit_reached.md",
  "request_id": "req_01jd3examplerequestid0000",
  "retryable": false
}
```

The `code` field is stable within `/v1`; `title` and `detail` may be reworded.
