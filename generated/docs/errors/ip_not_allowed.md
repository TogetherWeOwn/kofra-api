# Request address is not allowed for this token

Code: `ip_not_allowed`
HTTP status: 403
Retryable: no, not without a change

The API token is limited to some client addresses (`allowed_ips`), and this request came from another address. When a token is being created, an address list wider than the creating token's own is refused the same way.

## What to do

Send the request from an address in the token's `allowed_ips`, or use a token whose list includes this address.

## Example

```http
HTTP/1.1 403
Content-Type: application/problem+json
Kofra-Request-Id: req_01jd3examplerequestid0000
```

```json
{
  "type": "https://kofra.app/docs/errors/ip_not_allowed",
  "title": "Request address is not allowed for this token",
  "status": 403,
  "code": "ip_not_allowed",
  "detail": "The token is not accepted from 198.51.100.7.",
  "hint": "Send the request from an address in the token's `allowed_ips`, or use a token whose list includes this address.",
  "docs_url": "https://kofra.app/docs/errors/ip_not_allowed.md",
  "request_id": "req_01jd3examplerequestid0000",
  "retryable": false
}
```

The `code` field is stable within `/v1`; `title` and `detail` may be reworded.
