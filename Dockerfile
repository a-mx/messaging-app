FROM python:3.13-slim

RUN useradd --create-home appuser
WORKDIR /home/appuser/app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:appuser /home/appuser/app
USER appuser

ENV FLASK_APP=src
ENV FLASK_RUN_HOST=0.0.0.0

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]