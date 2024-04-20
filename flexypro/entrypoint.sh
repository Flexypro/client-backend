#!/bin/sh

python manage.py makemigrations api --no-input
python manage.py migrate api --no-input

python manage.py makemigrations --no-input
python manage.py migrate --no-input

python manage.py collectstatic --no-input

gunicorn flexypro.wsgi --bind 0.0.0.0:8000