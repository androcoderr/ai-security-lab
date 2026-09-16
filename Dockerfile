FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Presidio için gerekli spaCy dil modelini yüklüyoruz
RUN python -m spacy download en_core_web_lg

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
