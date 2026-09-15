from flask import Flask, request, jsonify
import requests
import psycopg2
import os
import markdown
import bleach
import redis

app = Flask(__name__)

# Çevre Değişkenleri (Docker servis isimleri)
DB_HOST = os.environ.get("DB_HOST", "db") 
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "mysecretpassword")
DB_NAME = os.environ.get("DB_NAME", "postgres")

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

# Redis Bağlantı Nesnesi (RAM tabanlı veritabanı)
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def check_rate_limit(identifier):
    """
    Kendi Rate Limiting Algoritmamız:
    - Her IP için Redis'te bir anahtar oluşturulur (örn: rate_limit:127.0.0.1)
    - İstek atıldığında bu değer 1 artırılır (INCR).
    - Eğer bu anahtar ilk kez oluşturuluyorsa, ömrü (TTL) 60 saniye olarak ayarlanır.
    - Sınır (örn: 5 istek) aşılırsa False döner, aşılmazsa True döner.
    """
    key = f"rate_limit:{identifier}"
    limit = 5  # 60 saniyede maksimum 5 istek
    window = 60 # Saniye cinsinden süre

    try:
        # Redis'te sayacı 1 artır (Eğer anahtar yoksa sıfırdan oluşturup 1 yapar)
        current = r.incr(key)
        
        # Eğer bu anahtar yeni oluşturulduysa (yani sayaç 1 ise), süresini başlat
        if current == 1:
            r.expire(key, window)
            
        # Sınırı kontrol et
        if current > limit:
            return False # Sınır aşıldı!
            
        return True # Devam edebilir
    except Exception as e:
        # Redis çökerse veya hata olursa sistemi kilitlememek (Fail-open) için True dönüyoruz
        print(f"Redis Hatası: {e}", flush=True)
        return True

def log_to_db(user_message, ai_response, threat_type):
    try:
        conn = psycopg2.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, dbname=DB_NAME)
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_prompt TEXT,
                ai_raw_response TEXT,
                threat_type VARCHAR(100)
            )
        ''')
        cur.execute('''
            INSERT INTO security_logs (user_prompt, ai_raw_response, threat_type)
            VALUES (%s, %s, %s)
        ''', (user_message, ai_response, threat_type))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Veritabanı Loglama Hatası: {e}", flush=True) 

def sanitize_ai_output(user_message, ai_response):
    html_version = markdown.markdown(ai_response)
    if "<img" in html_version or "<a " in html_version:
        log_to_db(user_message, ai_response, "Advanced SSRF/XSS Attempt Blocked")
        return "🛡️ SOC UYARISI: Profesyonel kalkan kılık değiştirmiş zararlı yükü tespit etti ve imha etti!"
    return ai_response

@app.route('/api/chat', methods=['POST'])
def chat():
    # 1. İstek atan kullanıcının IP adresini al (Rate limiting için kimlik)
    client_ip = request.remote_addr
    
    # 2. Rate Limit Kontrolü Yap
    if not check_rate_limit(client_ip):
        return jsonify({
            "reply": "⚠️ HIZ SINIRI AŞILDI: Çok fazla istek attınız. Lütfen 1 dakika bekleyin."
        }), 429 # HTTP 429: Too Many Requests

    user_message = request.json.get("message")
    
    ollama_payload = {
        "model": "llama3",
        "prompt": user_message,
        "stream": False
    }
    
    try:
        response = requests.post("http://ollama:11434/api/generate", json=ollama_payload)
        raw_ai_response = response.json().get("response", "")
        safe_response = sanitize_ai_output(user_message, raw_ai_response)
        return jsonify({"reply": safe_response})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
