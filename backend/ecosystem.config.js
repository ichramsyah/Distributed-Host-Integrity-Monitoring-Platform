module.exports = {
  apps: [{
    name: "django-api",
    script: "/home/webadm1/fim_backend_django/venv/bin/gunicorn",
    args: "--bind 0.0.0.0:5000 backend.wsgi:application --workers 3 --timeout 120 -k gevent",
    interpreter: "/home/webadm1/fim_backend_django/venv/bin/python3",
    exec_mode: "fork",
  }]
}
