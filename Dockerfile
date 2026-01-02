FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for PostgreSQL and timezone data
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    tzdata \
    postgresql-client \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create directories for PWA icons and avatars
RUN mkdir -p /app/static/icons /data/avatars

# Expose port
EXPOSE 8000

# Run the application with Gunicorn using the shared on_starting hook
CMD ["gunicorn", "-c", "gunicorn_conf.py", "app:app"]
