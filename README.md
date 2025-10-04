
+20
-0

# Password Manager

## Email verification configuration

The backend can send real verification emails when the application runs with a profile other than `dev`.
Set the following environment variables (or edit `backend/src/main/resources/application.yml`) to configure the SMTP sender:

| Variable | Description |
| --- | --- |
| `APP_MAIL_HOST` | SMTP host name. |
| `APP_MAIL_PORT` | SMTP port (defaults to `1025`). |
| `APP_MAIL_USERNAME` | SMTP username. |
| `APP_MAIL_PASSWORD` | SMTP password. |
| `APP_MAIL_FROM` | From address used for verification emails. |
| `APP_MAIL_SUBJECT_TEMPLATE` | `String.format` template for the subject. It receives the username as argument. |
| `APP_MAIL_BODY_TEMPLATE` | `String.format` template for the body. Use `\n` for new lines. It receives the username and verification link. |
| `APP_MAIL_SMTP_AUTH` | Toggle SMTP authentication (defaults to `true`). |
| `APP_MAIL_SMTP_STARTTLS` | Toggle STARTTLS (defaults to `true`). |

When developing locally, the `dev` profile is active and the application logs the verification link instead of sending an email. In any other profile the `SmtpEmailSender` bean sends the message using the configured SMTP server.

### Local development helpers

### Verification links

By default the backend generates verification links that point directly to the
`/api/auth/verify-email` endpoint exposed on `https://localhost:8443`.  If you
serve a web client from a different origin you can change the link target via
the `APP_AUTH_EMAIL_VERIFICATION_VERIFICATION_BASE_URL` environment variable (or
the `app.auth.email-verification.verification-base-url` property in
`application.yml`).  Provide the full URL up to, but not including, the `token`
value.  For example:

```bash
export APP_AUTH_EMAIL_VERIFICATION_VERIFICATION_BASE_URL="https://example.com/verify-email?token="
```

### Local development helpers

When developing locally you can rely on the bundled [MailHog](https://github.com/mailhog/MailHog) container instead of provisioning a real SMTP server:

```bash
docker compose up mailhog
```

The backend defaults to `localhost:1025`, which matches MailHog's SMTP listener. The captured messages are available at <http://localhost:8025>.

If the SMTP server cannot be reached, the backend now logs the verification link at `INFO` level so you can still confirm accounts during development or troubleshooting.

```bash
docker compose up mailhog
```

The backend defaults to `localhost:1025`, which matches MailHog's SMTP listener. The captured messages are available at <http://localhost:8025>.

If the SMTP server cannot be reached, the backend now logs the verification link at `INFO` level so you can still confirm accounts during development or troubleshooting.

## Backend build proxy configuration

The Maven wrapper reads additional options from `backend/.mvn/maven.config`.  By default the
configuration disables any proxy so Maven can connect to repositories directly.  If your
environment requires an HTTP(S) proxy you can enable it by providing the following system
properties when invoking Maven (or by exporting them via `MAVEN_OPTS`):

```bash
mvn \
  -DMAVEN_PROXY_ACTIVE=true \
  -DMAVEN_PROXY_PROTOCOL=https \
  -DMAVEN_PROXY_HOST=my-proxy-host \
  -DMAVEN_PROXY_PORT=8080 \
  -DMAVEN_PROXY_NON_PROXY_HOSTS="localhost|127.0.0.1|::1" \
  test
```

All fields are optional—leave `MAVEN_PROXY_ACTIVE` as `false` (the default) to force a direct
connection even if your shell exports `http_proxy`/`https_proxy`.  This avoids failures such as
`proxy: nodename nor servname provided, or not known` when a corporate proxy configuration is not
reachable from your current network.