The reviewed endpoint returned an unexpected record.

```bash
curl -i https://target.example/api/orders/8841
```

```http
HTTP/1.1 200 OK
Date: 2026-04-25T12:00:00Z
```

See `orders/controller.ts:88` and transaction `0x1234567890abcdef1234567890abcdef`.

