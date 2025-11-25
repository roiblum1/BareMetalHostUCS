FROM python:3.9-slim

WORKDIR /app

ENV PYTHONHTTPSVERIFY=0

# Install dependencies
COPY requirements.txt .
RUN pip3 install -r requirements.txt

# Copy source code
COPY src/ ./src/

ENV PYTHONPATH="${PYTHONPATH}:/app/src"

expose 8080

# Run the operator
CMD ["kopf", "run", "--liveness=http://0.0.0.0:8080/healthz", "/app/src/operator_bmh_gen.py", "--all-namespaces"]