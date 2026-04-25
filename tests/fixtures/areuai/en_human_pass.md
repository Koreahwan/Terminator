## Executive Summary

Testing revealed an IDOR in `api/accounts.ts:118`. The captured request below
uses account `acct_4812` while the token belongs to `acct_7731`.

```http
GET /api/accounts/acct_4812/invoices HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.demo
```

The server returned `HTTP/1.1 200 OK` at `2026-04-25T11:42:19Z` with invoice
data for the other account. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N.

