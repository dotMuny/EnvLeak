# API reference

All requests need an API key. Pass it as a header:

```http
GET /v1/things HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.PLACEHOLDER.SIGNATURE
X-Api-Key: {{ .ApiKey }}
```

Sample responses use placeholder identifiers:

```json
{
  "account_sid": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "auth_token": "your_auth_token",
  "webhook_secret": "whsec_REPLACE_ME"
}
```

Google Maps needs a browser key such as `AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`.
