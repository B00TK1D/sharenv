FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .

# Create vars directory
RUN mkdir -p /app/vars

# Expose port
EXPOSE 5000

# Run the server
CMD ["python", "server.py"]
