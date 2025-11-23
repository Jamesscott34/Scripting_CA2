FROM python:3.12-slim

WORKDIR /app

# Install shared dependencies for the whole project.
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir flask

# Copy only the insecure Flask app into the image (paths relative to repo root).
COPY flask_website/insecure_flask_app/ /app/

EXPOSE 5000

CMD ["python", "app.py"]


