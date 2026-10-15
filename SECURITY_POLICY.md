# AI Güvenlik Politikası — ai-security-lab

**Versiyon:** 1.0  
**Tarih:** Ekim 2026  
**Hazırlayan:** Security Engineering Team

---

## 1. Kapsam

Bu politika, ai-security-lab sistemini kullanan tüm kullanıcıları, geliştiricileri ve yöneticileri kapsar.

---

## 2. İzin Verilen Kullanımlar

- Genel bilgi soruları
- Kod yazma ve debug yardımı
- Belge özetleme (gizli olmayan belgeler)
- Eğitim ve araştırma amaçlı kullanım

---

## 3. Yasaklanan Kullanımlar

### 3.1 Gönderilemeyecek Veriler
- Kişisel kimlik bilgileri (TC kimlik, pasaport)
- Finansal bilgiler (kredi kartı, IBAN, banka hesabı)
- Şifreler ve API anahtarları
- Müşteri kişisel verileri
- Gizlilik dereceli kurumsal veriler

### 3.2 Yasak Eylemler
- Sistem güvenlik mekanizmalarını bypass etmeye çalışmak
- Prompt injection veya jailbreak girişimi
- Başka kullanıcıların verilerine erişmeye çalışmak
- Sistemi DoS saldırısına maruz bırakmak

---

## 4. Veri Sınıflandırması

| Sınıf | Tanım | AI'ya Gönderilebilir mi? |
|---|---|---|
| Kamuya Açık | Herkesin erişebildiği veri | ✅ Evet |
| Dahili | Şirket içi, gizli olmayan | ✅ Evet |
| Gizli | Sınırlı erişimli kurumsal veri | ⚠️ Dikkatli kullan |
| Çok Gizli | Kritik iş verisi, müşteri PII | ❌ Hayır |

---

## 5. Güvenlik Gereksinimleri

### 5.1 Kimlik Doğrulama
- Tüm API istekleri X-Chat-API-Key header içermelidir
- API anahtarları 90 günde bir yenilenmelidir
- Paylaşılan API anahtarı kullanılmamalıdır

### 5.2 Rate Limiting
- Her API anahtarı: 60 saniyede maksimum 20 istek
- Limit aşımı loglanır ve güvenlik ekibine bildirilir

### 5.3 Loglama
- Tüm istekler IP, user-agent ve endpoint bilgisiyle loglanır
- Loglar 90 gün saklanır
- Güvenlik olayları derhal güvenlik ekibine iletilir

---

## 6. İhlal Prosedürü

### 6.1 Tespit
Güvenlik ihlali şu yollarla tespit edilebilir:
- Otomatik anomali tespiti
- Manuel log incelemesi
- Kullanıcı bildirimi

### 6.2 Müdahale Adımları
1. İhlal eden IP/API key derhal engellenir
2. Güvenlik ekibi 15 dakika içinde bilgilendirilir
3. Olay kaydı oluşturulur (SECURITY_FINDINGS.md)
4. Etkilenen sistemler izole edilir
5. Kök neden analizi yapılır
6. Düzeltici önlemler alınır

### 6.3 Bildirim
- Kişisel veri ihlalinde KVKK gereği 72 saat içinde yetkili makama bildirim yapılır
- Etkilenen kullanıcılar bilgilendirilir

---

## 7. Sorumluluklar

| Rol | Sorumluluk |
|---|---|
| Kullanıcı | Politikaya uymak, şüpheli durumları bildirmek |
| Geliştirici | Güvenli kod yazmak, güvenlik testleri yapmak |
| Güvenlik Ekibi | İzleme, olay müdahalesi, politika güncelleme |
| Yönetim | Politikayı onaylamak ve kaynakları sağlamak |

---

## 8. Politika Güncelleme

Bu politika yılda en az bir kez veya önemli güvenlik olaylarından sonra gözden geçirilir.

---

## 9. İlgili Belgeler

- SECURITY_FINDINGS.md — Güvenlik bulguları
- README.md — Sistem dokümantasyonu
- OWASP Top 10 for LLM 2025

