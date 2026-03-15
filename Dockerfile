FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy API code and data
COPY app.py .
COPY scoring.py .
COPY data/ data/

EXPOSE 8402

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8402"]
