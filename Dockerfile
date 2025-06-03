FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Run as non-root user
RUN useradd -m -u 1000 operator && \
    chown -R operator:operator /app
USER operator

# Run the operator
CMD ["kopf", "run", "--liveness=http://0.0.0.0:8080/healthz", "/app/src/operator_bmh_gen.py", "--all-namespaces"]