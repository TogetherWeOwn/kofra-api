# Entries for the site's llms.txt files (handed to the site build)

## Root /llms.txt, section "API"

- [API quickstart](https://kofra.app/docs/api/quickstart.md): create a token, call the API with curl, the SDKs and the CLI
- [API reference (OpenAPI 3.1)](https://api.kofra.app/openapi.json): every operation, schema, example and error
- [Error catalogue](https://kofra.app/docs/errors/index.md): every error code with its fix
- [MCP quickstart](https://kofra.app/docs/mcp/quickstart.md): connect an AI client to the documentation MCP server
- [CLI quickstart](https://kofra.app/docs/cli/quickstart.md): the `kofra` command-line tool
- [S3 compatibility](https://kofra.app/docs/s3/compatibility.md): which S3 operations and tools work

## /docs/llms.txt, section "Errors"

- [validation_failed](https://kofra.app/docs/errors/validation_failed.md): Request is not valid
- [unknown_field](https://kofra.app/docs/errors/unknown_field.md): Request has a field the API does not know
- [invalid_bucket_name](https://kofra.app/docs/errors/invalid_bucket_name.md): Bucket name is not valid
- [invalid_cursor](https://kofra.app/docs/errors/invalid_cursor.md): Cursor is not valid
- [unauthenticated](https://kofra.app/docs/errors/unauthenticated.md): Authentication required
- [token_expired](https://kofra.app/docs/errors/token_expired.md): API token has expired
- [insufficient_scope](https://kofra.app/docs/errors/insufficient_scope.md): Token lacks a required scope
- [role_forbidden](https://kofra.app/docs/errors/role_forbidden.md): Your role does not allow this
- [account_read_only](https://kofra.app/docs/errors/account_read_only.md): Account is read-only
- [account_unavailable](https://kofra.app/docs/errors/account_unavailable.md): Account is not available
- [not_found](https://kofra.app/docs/errors/not_found.md): No such endpoint
- [bucket_not_found](https://kofra.app/docs/errors/bucket_not_found.md): Bucket not found
- [key_not_found](https://kofra.app/docs/errors/key_not_found.md): Access key not found
- [method_not_allowed](https://kofra.app/docs/errors/method_not_allowed.md): Method not allowed
- [payload_too_large](https://kofra.app/docs/errors/payload_too_large.md): Request body is too large
- [unsupported_media_type](https://kofra.app/docs/errors/unsupported_media_type.md): Body must be JSON
- [bucket_already_exists](https://kofra.app/docs/errors/bucket_already_exists.md): Bucket already exists
- [bucket_not_empty](https://kofra.app/docs/errors/bucket_not_empty.md): Bucket is not empty
- [key_limit_reached](https://kofra.app/docs/errors/key_limit_reached.md): Too many active access keys
- [grant_narrowing_refused](https://kofra.app/docs/errors/grant_narrowing_refused.md): Access can only be widened
- [grant_limit_reached](https://kofra.app/docs/errors/grant_limit_reached.md): Too many grants on one key
- [deletion_already_requested](https://kofra.app/docs/errors/deletion_already_requested.md): Deletion already requested
- [deletion_not_requested](https://kofra.app/docs/errors/deletion_not_requested.md): No deletion to cancel
- [deletion_final](https://kofra.app/docs/errors/deletion_final.md): Deletion can no longer be cancelled
- [feed_reset](https://kofra.app/docs/errors/feed_reset.md): Event feed was reset
- [idempotency_key_in_use](https://kofra.app/docs/errors/idempotency_key_in_use.md): Same request is still running
- [idempotency_key_reused](https://kofra.app/docs/errors/idempotency_key_reused.md): Idempotency key used with another request
- [rate_limited](https://kofra.app/docs/errors/rate_limited.md): Too many requests
- [internal_error](https://kofra.app/docs/errors/internal_error.md): Internal error
- [service_unavailable](https://kofra.app/docs/errors/service_unavailable.md): Service is busy
