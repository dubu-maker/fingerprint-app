# Fingerprinting App

## Environment Variables
- `SECRET_KEY`: Flask session signing key. Set to a strong random value in production.
- `FINGERPRINT_SECRET`: Secret used to sign watermark tokens. Must match across all app instances.
- `ALLOWED_UPLOAD_EXTENSIONS`: Optional comma-separated list of file extensions (e.g. `png,jpg,mp4`). Defaults to `png,jpg,jpeg,gif` when unset.
- `ENABLE_SECURE_COOKIES`: Set to `1` (default) to send cookies with the `Secure` flag; set to `0` for local HTTP testing.
- `FORCE_HTTPS`: Redirects all traffic to HTTPS when `1` (default). Disable by setting to `0` in local development.
- `RATELIMIT_STORAGE_URI`: Optional storage backend URI for Flask-Limiter (defaults to in-memory).
- `WTF_CSRF_TIME_LIMIT`: Lifetime in seconds for CSRF tokens (defaults to `3600`).

Adjust these values in your deployment environment (e.g., Render dashboard or `.env` file) before starting the server.
