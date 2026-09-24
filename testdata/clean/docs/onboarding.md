# Onboarding

Ask an admin for credentials, then fill in `.env`:

```dotenv
GITHUB_TOKEN=ghp_REPLACE_WITH_YOUR_TOKEN_000000000
GITLAB_TOKEN=glpat-XXXXXXXXXXXXXXXXXXXX
SLACK_BOT_TOKEN=xoxb-000000000000-000000000000-XXXXXXXXXXXXXXXXXXXXXXXX
STRIPE_SECRET_KEY=sk_live_EXAMPLE00000000000000000
SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token_here
NPM_TOKEN=npm_000000000000000000000000000000000000
DOCKERHUB_TOKEN=dckr_pat_example_value_here
```

The production database URL looks like:

    postgres://readonly:<password>@db.internal:5432/app
    mysql://root:password@localhost:3306/app
    redis://:${REDIS_PASSWORD}@cache:6379/0
    mongodb+srv://svc:<password>@cluster0.example.mongodb.net/app

For local TLS, generate your own key — never commit one:

    openssl genrsa -out server.key 4096   # writes -----BEGIN RSA PRIVATE KEY-----

Google Maps: `AIzaSy0000000000000000000000000000000`.
Sentry: `https://<publicKey>@o0.ingest.sentry.io/0`.
Slack webhook: `https://hooks.slack.com/services/T00000000/B00000000/000000000000000000000000`.
