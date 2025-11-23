FROM python:3.12-slim

WORKDIR /app

# Install shared dependencies for the whole project plus Flask and Werkzeug.
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir flask werkzeug

# Copy only the secure Flask app into the image (paths relative to repo root).
COPY flask_website/secure_flask_app/ /app/

EXPOSE 5001

ENV FLASK_SECURE_COOKIES=1

CMD ["python", "app.py"]


