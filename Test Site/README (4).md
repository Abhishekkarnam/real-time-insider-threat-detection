# NovaTech Solutions — Auth Testing Site

A realistic enterprise authentication testing website built with React (CDN), no build step required.

## Features
- Sign in with email + password
- Multi-factor authentication (TOTP / SMS)
- Forgot password flow
- Account recovery codes
- Two-step registration with password strength meter
- Dashboard with session management
- Security settings panel

## Test Credentials
| Field | Value |
|---|---|
| Email | `demo@novatech.io` |
| Password | `Demo@1234` |
| MFA Code | `123456` |
| Recovery Code | `NOVA-TECH-2024-ABCD` |

## Deploy
This is a static single-file app. Deploy anywhere that serves HTML.

### Vercel
```bash
npx vercel --prod
```

### Local
Just open `index.html` in a browser.
