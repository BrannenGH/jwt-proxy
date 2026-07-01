FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    JWT_PROXY_HOST=0.0.0.0 \
    JWT_PROXY_PORT=8080

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY jwt_proxy.py .

EXPOSE 8080

CMD ["python", "/app/jwt_proxy.py"]
