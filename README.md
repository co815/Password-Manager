# Password Manager

A secure, encrypted password manager with a modern React frontend and Spring Boot backend. Store your credentials safely with end-to-end encryption, WebAuthn passkey support, and multi-factor authentication.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Java](https://img.shields.io/badge/Java-21-orange)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3-green)
![React](https://img.shields.io/badge/React-19-blue)
![MongoDB](https://img.shields.io/badge/MongoDB-7-green)

---

## Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Quick Start Guide](#-quick-start-guide)
- [Detailed Setup](#-detailed-setup)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Start MongoDB](#2-start-mongodb)
  - [3. Configure the Backend](#3-configure-the-backend)
  - [4. Run the Backend](#4-run-the-backend)
  - [5. Run the Frontend](#5-run-the-frontend)
- [Configuration Reference](#-configuration-reference)
- [Usage Guide](#-usage-guide)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

---

## Overview

This Password Manager is a full-stack web application that helps you securely store and manage your credentials. All sensitive data is encrypted client-side before being sent to the server, ensuring that even if the database is compromised, your passwords remain protected.

### How It Works

1. **Registration**: When you create an account, a master password is used to derive encryption keys using Argon2
2. **Encryption**: Your Data Encryption Key (DEK) is wrapped with a Key Encryption Key (KEK) derived from your master password
3. **Storage**: Only encrypted credentials are stored on the server - the server never sees your plaintext passwords
4. **Decryption**: When you log in and enter your master password, credentials are decrypted locally in your browser

---

## Features

| Feature | Description |
|---------|-------------|
| **End-to-End Encryption** | Client-side AES-GCM encryption - server never sees plaintext |
| **WebAuthn/Passkeys** | Passwordless authentication with biometrics or security keys |
| **TOTP Support** | Store and generate 2FA codes for your accounts |
| **Master Password Rotation** | Securely rotate your master password without losing data |
| **Import/Export** | Backup and restore your encrypted vault |
| **Audit Logging** | Track access and changes to your vault |
| **Modern UI** | Beautiful Material UI design with dark mode support |
| **Rate Limiting** | Protection against brute-force attacks |
| **Email Verification** | Verify user accounts via email |
| **reCAPTCHA** | Optional captcha protection for authentication |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                           Frontend                               │
│  React 19 + Vite + Material UI + TypeScript                     │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  • Client-side encryption (AES-GCM, Argon2)                │ │
│  │  • WebAuthn credential management                           │ │
│  │  • TOTP code generation                                     │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ HTTPS / API calls
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                           Backend                                │
│  Spring Boot 3.3 + Spring Security + Java 21                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  • JWT authentication                                       │ │
│  │  • WebAuthn server-side verification                        │ │
│  │  • Rate limiting (Bucket4j)                                 │ │
│  │  • Audit logging                                            │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                          Database                                │
│                       MongoDB 7                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  • User accounts and profiles                               │ │
│  │  • Encrypted vault items                                    │ │
│  │  • WebAuthn credentials                                     │ │
│  │  • Audit logs                                               │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

Before you begin, ensure you have the following installed:

| Tool | Version | Check Command | Installation |
|------|---------|---------------|--------------|
| **Java JDK** | 21+ | `java -version` | [Download](https://adoptium.net/) |
| **Node.js** | 18+ | `node --version` | [Download](https://nodejs.org/) |
| **pnpm** | 8+ | `pnpm --version` | `npm install -g pnpm` |
| **Docker** | Latest | `docker --version` | [Download](https://docker.com/) |
| **Git** | Latest | `git --version` | [Download](https://git-scm.com/) |

> **Tip**: You can also use npm or yarn instead of pnpm, but pnpm is recommended for faster installs.

---

## Quick Start Guide

If you want to get up and running quickly, follow these steps:

```bash
# 1. Clone the repository
git clone https://github.com/your-username/Password-Manager.git
cd Password-Manager

# 2. Start MongoDB (and optionally MailHog for email testing)
docker compose up -d

# 3. Start the backend (in a new terminal)
cd backend
./mvnw spring-boot:run

# 4. Start the frontend (in another terminal)
cd frontend
pnpm install
pnpm dev
```

Then open your browser to **http://localhost:5173** 

---

## Detailed Setup

### 1. Clone the Repository

```bash
git clone https://github.com/co815/Password-Manager.git
cd Password-Manager
```

### 2. Start MongoDB

The project includes a `docker-compose.yml` that provides MongoDB and MailHog (for email testing).

```bash
# Start only MongoDB
docker compose up mongodb -d

# Or start both MongoDB and MailHog (recommended for development and creating the account you will test the application)
docker compose up -d
```

**Verify MongoDB is running:**
```bash
docker compose ps
```

You should see the mongodb container with status "Up".

> **MailHog**: If you started MailHog, you can view captured emails at http://localhost:8025

### 3. Configure the Backend

Navigate to the backend directory and create your environment file:

```bash
cd backend
```

Create a `.env` file with the following required variables:

```bash
# .env file in the backend directory

# Required: Secret for JWT token signing (use a long random string)
APP_JWT_SECRET=your-super-secret-jwt-key-at-least-32-characters-long

# Required: Salt for password hashing placeholder (use a random string)
APP_AUTH_PLACEHOLDER_SALT_SECRET=another-random-secret-string-here

# Optional: Comma-separated list of admin emails for audit log access
APP_AUDIT_ADMIN_EMAILS=admin@example.com
```

> **🔐 Security Note**: Generate strong random secrets for production. You can use:
> ```bash
> openssl rand -base64 48
> ```

### 4. Run the Backend

Make sure you're in the `backend` directory:

```bash
cd backend

# Build and run the application
./mvnw spring-boot:run
```

**First run will take longer** as Maven downloads dependencies.

**Expected output:**
```
...
Started PmApplication in X.XXX seconds
```

The backend API is now available at **http://localhost:8080/api**

> **Windows Users**: Use `mvnw.cmd` instead of `./mvnw`

### 5. Run the Frontend

Open a **new terminal** and navigate to the frontend directory:

```bash
cd frontend

# Install dependencies
pnpm install

# Start the development server
pnpm dev
```

**Expected output:**
```
  VITE v7.x.x  ready in XXX ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

Open your browser to **http://localhost:5173** 🎉

---

## Configuration Reference

### Environment Variables

#### Backend (`backend/.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `APP_JWT_SECRET` | ✅ Yes | - | Secret key for JWT signing (min 32 chars) |
| `APP_AUTH_PLACEHOLDER_SALT_SECRET` | ✅ Yes | - | Salt for password hashing placeholder |
| `APP_AUDIT_ADMIN_EMAILS` | No | - | Comma-separated admin emails for audit access |
| `APP_AUTH_CAPTCHA_PROVIDER` | No | `none` | Set to `recaptcha` to enable Google reCAPTCHA |
| `APP_AUTH_CAPTCHA_SITE_KEY` | No | - | Google reCAPTCHA site key |
| `APP_AUTH_CAPTCHA_SECRET` | No | - | Google reCAPTCHA secret key |

#### Email Configuration (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_MAIL_HOST` | `localhost` | SMTP server hostname |
| `APP_MAIL_PORT` | `1025` | SMTP server port |
| `APP_MAIL_USERNAME` | `test` | SMTP authentication username |
| `APP_MAIL_PASSWORD` | `test` | SMTP authentication password |
| `APP_MAIL_FROM` | `no-reply@example.com` | Sender email address |

### Configuring Google reCAPTCHA (Optional)

To enable CAPTCHA protection on login/signup:

1. Get your keys from [Google reCAPTCHA Admin](https://www.google.com/recaptcha/admin)
2. Add to your `.env` file:
   ```bash
   APP_AUTH_CAPTCHA_PROVIDER=recaptcha
   APP_AUTH_CAPTCHA_SITE_KEY=your-site-key
   APP_AUTH_CAPTCHA_SECRET=your-secret-key
   ```
3. Restart the backend

---

## Usage Guide

### Creating an Account

1. Navigate to http://localhost:5173
2. Click "Sign Up" to switch to the registration form
3. Enter your details:
   - **Email**: Your email address (used for login)
   - **Username**: Display name
   - **Master Password**: This encrypts all your data 
4. Click "Sign Up" to create your account
5. If email verification is enabled, check your email (or MailHog at http://localhost:8025)

### Logging In

1. Enter your email and master password
2. If you have a passkey registered, you can use it for passwordless login
3. After login, your vault is decrypted client-side

### Managing Credentials

| Action | How To |
|--------|--------|
| **Add credential** | Click the `+` button in the sidebar |
| **View credential** | Click on any item in the sidebar |
| **Edit credential** | Click the edit icon when viewing a credential |
| **Delete credential** | Click the delete icon when viewing a credential |
| **Copy password** | Click the copy icon next to the password field |
| **Generate password** | Click the magic wand icon when adding/editing |
| **Toggle favorite** | Click the star icon |

### Setting Up Passkeys (WebAuthn)

1. Go to Settings (gear icon in the sidebar)
2. Click "Register Passkey"
3. Follow your browser's prompts to register your biometric/security key
4. Now you can log in without typing your password!

### Exporting Your Vault

1. Go to Settings
2. Click "Export Vault"
3. Your encrypted `.pmvault` file will be downloaded

### Importing a Vault

1. Go to Settings
2. Click "Import" and select your `.pmvault` file
3. Items will be merged with your existing vault

---

## 🔧 Troubleshooting

### Common Issues

<details>
<summary><strong>⚠️ MongoDB connection refused</strong></summary>

**Symptom**: Backend fails to start with connection errors

**Solution**:
1. Check if Docker is running: `docker ps`
2. Verify MongoDB container is up: `docker compose ps`
3. Restart MongoDB: `docker compose restart mongodb`
</details>

<details>
<summary><strong>⚠️ "APP_JWT_SECRET is required" error</strong></summary>

**Symptom**: Backend fails to start

**Solution**:
1. Make sure you created the `.env` file in the `backend` directory
2. Verify the file contains `APP_JWT_SECRET=your-secret-here`
3. The secret must be at least 32 characters long
</details>

<details>
<summary><strong>⚠️ Frontend can't connect to backend</strong></summary>

**Symptom**: API calls fail with network errors

**Solution**:
1. Verify backend is running on port 8080
2. Check the Vite proxy config in `frontend/vite.config.ts`
3. Make sure you're accessing the frontend via http://localhost:5173
</details>

<details>
<summary><strong>⚠️ "Master password invalid" when unlocking</strong></summary>

**Symptom**: Can't access vault after logging in

**Solution**:
1. The master password is case-sensitive - check caps lock
2. If you forgot your password, there's no recovery (by design for security)
3. Create a new account if necessary
</details>

<details>
<summary><strong>⚠️ Email verification link not received</strong></summary>

**Symptom**: Registration seems stuck waiting for verification

**Solution**:
1. If using MailHog, check http://localhost:8025
2. In development mode, the verification link is logged to console
3. Check the backend logs for the verification URL
</details>

### Getting Help

If you encounter issues not covered here:

1. Check the backend logs in your terminal
2. Check browser developer tools (F12) for frontend errors
3. Open an issue on GitHub with details about your problem

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [Spring Boot](https://spring.io/projects/spring-boot) - Backend framework
- [React](https://react.dev/) - Frontend library
- [Material UI](https://mui.com/) - Component library
- [Yubico WebAuthn](https://github.com/Yubico/java-webauthn-server) - WebAuthn server implementation
- [Argon2](https://github.com/nicolo-ribaudo/hash-wasm) - Password hashing
- [MailHog](https://github.com/mailhog/MailHog) - Email testing tool
