FROM python:3.9

WORKDIR /app

COPY requirements.txt .

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies and helper tools
RUN apt-get update && apt-get install -y jq curl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure helper scripts are executable inside the container
RUN chmod +x /app/helpers/*.sh

# Change permissions for the sboms and tmp directories
RUN mkdir -p /app/sboms /app/tmp && \
    chmod -R 777 /app/sboms /app/tmp  
    # Set permissions to allow read/write for all

CMD ["python", "app.py"]
