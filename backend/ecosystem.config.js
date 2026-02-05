/**
 * ============================================================================
 * ⚠ DISCLAIMER
 * This PM2 ecosystem configuration is intended for portfolio and showcase
 * purposes only. It demonstrates a production-like process management setup
 * for a Django application.
 *
 * Actual production environments may use different process managers,
 * hardened configurations, and secure environment handling.
 * ============================================================================
 */

module.exports = {
  apps: [
    {
      name: 'fim-backend-core',
      cwd: '.', // Set Current Working Directory to project root

      script: './venv/bin/gunicorn',
      interpreter: './venv/bin/python3',

      args: '--bind 0.0.0.0:8000 backend.wsgi:application --workers 3 --timeout 120 -k gevent',

      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',

      env: {
        DJANGO_SETTINGS_MODULE: 'backend.settings',
        PYTHONUNBUFFERED: '1',
      },
      env_production: {
        DJANGO_SETTINGS_MODULE: 'backend.settings',
        NODE_ENV: 'production',
      },
    },
  ],
};
