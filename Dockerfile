FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for PostgreSQL and timezone data
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    tzdata \
    postgresql-client \
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

# Run the application with Gunicorn
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:8000", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
