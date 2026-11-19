FROM python:3.12-slim

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Only the fixed app ships. The vulnerable demo stays out of the image.
COPY app/__init__.py app/__init__.py
COPY app/secure_app.py app/secure_app.py

RUN useradd --create-home appuser
USER appuser

EXPOSE 8080
CMD ["uvicorn", "app.secure_app:app", "--host", "0.0.0.0", "--port", "8080"]
