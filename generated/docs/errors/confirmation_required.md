# A person must confirm this in the console

Code: `confirmation_required`
HTTP status: 403
Retryable: no, not without a change

The action cannot be undone or lets a credential do more (deleting a bucket, creating an access key that can write, adding or widening a grant, cancelling a scheduled account deletion), so a signed-in member must confirm it in the console. A request with an API token, an agent's included, cannot confirm it, whatever its scopes. Cancelling a scheduled account deletion also needs the console's confirmation page.

## What to do

Do this in the console; a script that must write or delete objects without a person uses an S3 access key instead.

## Example

```http
HTTP/1.1 403
Content-Type: application/problem+json
Kofra-Request-Id: req_01jd3examplerequestid0000
```

```json
{
  "type": "https://kofra.app/docs/errors/confirmation_required",
  "title": "A person must confirm this in the console",
  "status": 403,
  "code": "confirmation_required",
  "detail": "Deleting a bucket needs a confirmation in the console.",
  "hint": "Do this in the console; a script that must write or delete objects without a person uses an S3 access key instead.",
  "docs_url": "https://kofra.app/docs/errors/confirmation_required.md",
  "request_id": "req_01jd3examplerequestid0000",
  "retryable": false
}
```

The `code` field is stable within `/v1`; `title` and `detail` may be reworded.
