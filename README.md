
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
`proxy.active` flag is set to `false`, which lets Maven talk to repositories directly.  If
your environment requires an HTTP(S) proxy, enable it when invoking Maven:

```bash
mvn -Dproxy.active=true -Dproxy.host=my-proxy-host -Dproxy.port=8080 test
```

All proxy attributes (`proxy.active`, `proxy.protocol`, `proxy.host`, `proxy.port`, and
`proxy.nonProxyHosts`) can be overridden via system properties or `MAVEN_OPTS` environment
variables.  When the proxy host configured by your environment is unreachable and Maven fails
with `proxy: nodename nor servname provided`, re-run the command with `-Dproxy.active=false` to
force a direct connection.