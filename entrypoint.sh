#!/bin/sh
set -e

python -m src.init_db

exec gunicorn --bind 0.0.0.0:8000 --workers 4 "run:app"