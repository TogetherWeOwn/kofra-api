# Token is limited to other buckets

Code: `bucket_not_allowed`
HTTP status: 403
Retryable: no, not without a change

The API token is limited to some buckets (`buckets`), and the request names a bucket outside that list. When a token or an access key is being created, a bucket outside the creating token's list is refused the same way.

## What to do

Use a token whose `buckets` list includes this bucket, or a token without a bucket limit.

## Example

```http
HTTP/1.1 403
Content-Type: application/problem+json
Kofra-Request-Id: req_01jd3examplerequestid0000
```

```json
{
  "type": "https://kofra.app/docs/errors/bucket_not_allowed",
  "title": "Token is limited to other buckets",
  "status": 403,
  "code": "bucket_not_allowed",
  "detail": "The token is limited to other buckets than \"photos\".",
  "hint": "Use a token whose `buckets` list includes this bucket, or a token without a bucket limit.",
  "docs_url": "https://kofra.app/docs/errors/bucket_not_allowed.md",
  "request_id": "req_01jd3examplerequestid0000",
  "retryable": false
}
```

The `code` field is stable within `/v1`; `title` and `detail` may be reworded.
