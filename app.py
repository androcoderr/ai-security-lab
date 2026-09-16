from flask import Flask, request, jsonify
import requests
import psycopg2
import os
import markdown
import bleach
import redis
from presidio_analyzer import AnalyzerEngine

app = Flask(__name__)

analyzer = AnalyzerEngine()

DB_HOST = os.environ.get("DB_HOST", "db") 
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "mysecretpassword")
DB_NAME = os.environ.get("DB_NAME", "postgres")

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def check_rate_limit(identifier):
    key = f"rate_limit:{identifier}"
    limit = 5 
    window = 60 
    try:
        current = r.incr(key)
        if current == 1:
            r.expire(key, window)
        if current > limit:
            return False 
        return True
    except Exception:
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

def detect_pii(text):
    results = analyzer.analyze(text=text, entities=["CREDIT_CARD", "PHONE_NUMBER", "EMAIL_ADDRESS", "IBAN_CODE"], language='en')
    return results

@app.route('/api/chat', methods=['POST'])
def chat():
    client_ip = request.remote_addr
    if not check_rate_limit(client_ip):
        return jsonify({"reply": "⚠️ HIZ SINIRI AŞILDI: Çok fazla istek attınız."}), 429

    user_message = request.json.get("message", "")

    pii_results = detect_pii(user_message)
    if pii_results:
        detected_entities = [res.entity_type for res in pii_results]
        log_to_db(user_message, "Blocked by Presidio DLP", f"PII Leak Attempt: {', '.join(detected_entities)}")
        return jsonify({"reply": f"🛡️ DLP UYARISI: Mesajınızda hassas veri tespit edildi! Algılanan: {', '.join(detected_entities)}"}), 400

    ollama_payload = {
        "model": "llama3",
        "prompt": user_message,
        "stream": False
    }
    
    try:
        response = requests.post("http://ollama:11434/api/generate", json=ollama_payload)
        raw_ai_response = response.json().get("response", "")
        
        ai_pii_results = detect_pii(raw_ai_response)
        if ai_pii_results:
            log_to_db(user_message, raw_ai_response, "AI Output PII Leak Prevented")
            raw_ai_response = "🛡️ DLP Kalkanı: Yapay zekanın ürettiği yanıt hassas veri içerdiği için engellendi."

        return jsonify({"reply": raw_ai_response})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/dashboard', methods=['GET'])
def soc_dashboard():
    logs = []
    try:
        conn = psycopg2.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, dbname=DB_NAME)
        cur = conn.cursor()
        cur.execute('SELECT id, timestamp, user_prompt, threat_type FROM security_logs ORDER BY timestamp DESC LIMIT 20;')
        logs = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Dashboard Veritabanı Okuma Hatası: {e}", flush=True)

    html_content = """
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <title>AI Security Lab - SOC Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 30px; }
            h1 { color: #38bdf8; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #1e293b; border-radius: 8px; overflow: hidden; }
            th, td { padding: 14px; border-bottom: 1px solid #334155; text-align: left; }
            th { background: #0284c7; color: white; }
            tr:hover { background: #334155; }
            .badge { background: #ef4444; color: white; padding: 6px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }
            .refresh-btn { display: inline-block; margin-top: 15px; background: #0ea5e9; color: white; padding: 10px 16px; text-decoration: none; border-radius: 6px; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>🛡️ AI Security Lab - SOC Tehdit Paneli</h1>
        <a href="/admin/dashboard" class="refresh-btn">🔄 Paneli Yenile</a>
        <table>
            <tr>
                <th>ID</th>
                <th>Zaman (UTC)</th>
                <th>Kullanıcı Komutu (Prompt)</th>
                <th>Tehdit Türü</th>
            </tr>
    """
    
    if not logs:
        html_content += '<tr><td colspan="4" style="text-align: center; color: #94a3b8;">Henüz kayıtlı bir güvenlik ihlali bulunmuyor.</td></tr>'
    else:
        for log in logs:
            html_content += f'<tr><td>{log[0]}</td><td>{log[1]}</td><td>{log[2]}</td><td><span class="badge">{log[3]}</span></td></tr>'
        
    html_content += "</table></body></html>"
    return html_content

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
