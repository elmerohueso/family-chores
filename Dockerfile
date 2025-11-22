FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for PostgreSQL and timezone data
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "-u","app.py"]
