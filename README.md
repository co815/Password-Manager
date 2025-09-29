
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