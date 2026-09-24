# Example Service

## Configuration

Set the following before starting:

```sh
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export STRIPE_SECRET_KEY=sk_live_your_key_here
export OPENAI_API_KEY=sk-proj-REDACTED
export SLACK_WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
```

Or in `.env`:

```
DATABASE_URL=postgres://user:<password>@localhost:5432/db
REDIS_URL=redis://:${REDIS_PASSWORD}@localhost:6379/0
MONGODB_URI=mongodb://admin:changeme@localhost:27017
SERVICE_API_TOKEN=your-api-key-here
```

Authentication uses a bearer token:

    Authorization: Bearer <YOUR_ACCESS_TOKEN>

Private keys live in `config/`, never in the repository:

    -----BEGIN RSA PRIVATE KEY-----
    (your key goes here)
    -----END RSA PRIVATE KEY-----
