from flask import Flask, request, jsonify
import requests
import re

app = Flask(__name__)

def sanitize_ai_output(ai_response):
    # Savunma 1: Markdown görsellerini ![...](...) yakalayan Regex kalkanı
    markdown_image_pattern = r'!\[.*?\]\(.*?\)'
    
    # Savunma 2: Eğer model kandırılıp link üretmişse, metni imha et!
    if re.search(markdown_image_pattern, ai_response) or "http" in ai_response:
        return "🛡️ SİSTEM UYARISI: Güvenlik politikası gereği dış bağlantılar engellenmiştir! Bu teşebbüs loglanmıştır."
    
    return ai_response

@app.route('/api/chat', methods=['POST'])
def chat():
    user_message = request.json.get("message")
    
    ollama_payload = {
        "model": "llama3",
        "prompt": user_message,
        "stream": False
    }
    
    try:
        response = requests.post("http://ollama:11434/api/generate", json=ollama_payload)
        raw_ai_response = response.json().get("response", "")
        
        # MAVİ TAKIM DEVREDE: Çıktıyı dışarı basmadan önce filtreden geçiriyoruz
        safe_response = sanitize_ai_output(raw_ai_response)
        
        return jsonify({"reply": safe_response})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
