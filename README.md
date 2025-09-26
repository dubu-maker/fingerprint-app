# Fingerprinting App

## Environment Variables
- `SECRET_KEY`: Flask session signing key. Set to a strong random value in production.
- `FINGERPRINT_SECRET`: Secret used to sign watermark tokens. Must match across all app instances.
- `DATABASE_URL`: SQLAlchemy connection string. If omitted, the app falls back to `sqlite:///database.db` inside the project directory.
- `ALLOWED_UPLOAD_EXTENSIONS`: Optional comma-separated list of file extensions (e.g. `png,jpg,mp4`). Defaults to `png,jpg,jpeg,gif,bmp,tiff,webp,mp4,mov,avi,mkv,webm` when unset.
- `FFMPEG_BIN`: Path to the ffmpeg executable (defaults to `ffmpeg`). Required to keep audio tracks when watermarking video.
- `ENABLE_SECURE_COOKIES`: Set to `1` (default) to send cookies with the `Secure` flag; set to `0` for local HTTP testing.
- `FORCE_HTTPS`: Redirects all traffic to HTTPS when `1` (default). Disable by setting to `0` in local development.
- `RATELIMIT_STORAGE_URI`: Optional storage backend URI for Flask-Limiter (defaults to in-memory).
- `WTF_CSRF_TIME_LIMIT`: Lifetime in seconds for CSRF tokens (defaults to `3600`).
- `WATERMARK_DCT_DELTA`: Strength factor for the DCT watermark embedding (defaults to `6.0`). Increase cautiously for higher robustness.
- `USE_TASK_QUEUE`: Enable background processing via RQ when set to `1` (requires Redis).
- `REDIS_URL`: Connection string for Redis (defaults to `redis://localhost:6379/0`).
- `TASK_QUEUE_NAME`: Optional queue name (defaults to `fingerprinting`).
- `TASK_QUEUE_THRESHOLD_MB`: When RQ is enabled, files at or above this size (in MB) are processed asynchronously (defaults to `100`).

Adjust these values in your deployment environment (e.g., Render dashboard or `.env` file) before starting the server.

## Background Processing

When `USE_TASK_QUEUE=1` the application enqueues watermark jobs instead of running them inside the request. Start an RQ worker next to the web process:

```
rq worker fingerprinting --url "$REDIS_URL"
```

Large video uploads (or files above `TASK_QUEUE_THRESHOLD_MB`) will now be processed asynchronously while the user watches a progress page.

## Video Audio Preservation

Install ffmpeg and ensure `FFMPEG_BIN` points to the executable. During video watermarking the app extracts the original audio, embeds the fingerprint into video frames, and remuxes the audio back so previews and downloads keep sound intact.

