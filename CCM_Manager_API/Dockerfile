FROM python:3.9

WORKDIR /app

COPY requirements.txt .

# Install dependencies, including CycloneDX
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install cyclonedx-bom
RUN apt-get update && apt-get install -y jq curl && rm -rf /var/lib/apt/lists/*

COPY . .

# Change permissions for the sboms and tmp directories
RUN mkdir -p /app/sboms /app/tmp && \
    chmod -R 777 /app/sboms /app/tmp  
    # Set permissions to allow read/write for all

#CMD ["python", "app.py"]
