FROM python:3.11-slim

WORKDIR /app

ENV PYTHONHTTPSVERIFY=0

# Install dependencies
COPY requirements.txt .
RUN pip3 install -r requirements.txt

# Copy source code
COPY src/ ./src/

ENV PYTHONPATH="${PYTHONPATH}:/app/src"

EXPOSE 8080

# Run the operator using python -m to avoid arch-specific entry-point wrapper
CMD ["python", "-m", "kopf", "run", "--verbose", "--liveness=http://0.0.0.0:8080/healthz", "/app/src/operator_bmh_gen.py", "--all-namespaces"]