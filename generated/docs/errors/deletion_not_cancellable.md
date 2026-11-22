# Deletion cannot be cancelled here

Code: `deletion_not_cancellable`
HTTP status: 409
Retryable: no, not without a change

The deletion was not started by a member of the account (for example, it was started for non-payment), so it cannot be cancelled through the API or the console.

## What to do

Contact support with the `request_id` to resolve what started the deletion.

## Example

```http
HTTP/1.1 409
Content-Type: application/problem+json
Kofra-Request-Id: req_01jd3examplerequestid0000
```

```json
{
  "type": "https://kofra.app/docs/errors/deletion_not_cancellable",
  "title": "Deletion cannot be cancelled here",
  "status": 409,
  "code": "deletion_not_cancellable",
  "detail": "This deletion was not requested by a member of the account.",
  "hint": "Contact support with the `request_id` to resolve what started the deletion.",
  "docs_url": "https://kofra.app/docs/errors/deletion_not_cancellable.md",
  "request_id": "req_01jd3examplerequestid0000",
  "retryable": false
}
```

The `code` field is stable within `/v1`; `title` and `detail` may be reworded.
