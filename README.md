# 🛡️ Honeypot Erken Uyarı Sistemi

Kurumsal ağ mimarilerini hedef alan siber tehditleri tespit etmek ve analiz etmek üzere tasarlanmış **proaktif erken uyarı sistemi**.

## 📋 Sistem Mimarisi

```
┌─────────────────────────────────────────────────────────┐
│                    Ana Orkestratör (main.py)             │
├─────────────┬──────────────┬──────────────┬─────────────┤
│ SSH Honeypot│ FTP Honeypot │ HTTP Honeypot│ PCAP Capture│
│  (port 2222)│  (port 2121) │  (port 8080) │  (Scapy)    │
├─────────────┴──────────────┴──────────────┴─────────────┤
│              Merkezi Loglama (logger.py)                 │
│              JSON-Lines formatı (.jsonl)                 │
├─────────────────────────────────────────────────────────┤
│           Erken Uyarı Motoru (alert_engine.py)          │
│     Brute-force │ Port scan │ Malware │ Priv-esc        │
├─────────────────────────────────────────────────────────┤
│         Analiz & Raporlama (analyzer.py)                │
│              HTML │ JSON rapor üretimi                   │
├─────────────────────────────────────────────────────────┤
│           Web Dashboard (dashboard.py)                   │
│          Flask │ Gerçek zamanlı izleme                   │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Kurulum

### 1. Gereksinimler
- Python 3.9+
- VirtualBox (izole ağ ortamı için)
- Kali Linux VM (saldırı simülasyonu için)

### 2. Bağımlılıkları Yükle
```bash
pip install -r requirements.txt
```

### 3. Sistemi Başlat
```bash
# Tüm servisleri başlat
python main.py

# Özel yapılandırma dosyası ile
python main.py --config my_config.yaml

# Dashboard olmadan
python main.py --no-dashboard

# Sadece rapor üret
python main.py --report
```

## 📁 Proje Yapısı

```
code/
├── main.py              # Ana orkestratör - tüm modülleri yönetir
├── config.yaml          # Yapılandırma dosyası
├── logger.py            # Merkezi JSON-lines loglama
├── ssh_honeypot.py      # Sahte SSH servisi (Paramiko)
├── ftp_honeypot.py      # Sahte FTP servisi (Socket)
├── http_honeypot.py     # Sahte HTTP servisi (Socket)
├── pcap_capture.py      # PCAP ağ trafiği yakalama (Scapy)
├── alert_engine.py      # Erken uyarı / alarm motoru
├── analyzer.py          # Log analizi ve HTML rapor üretimi
├── dashboard.py         # Flask web dashboard
├── requirements.txt     # Python bağımlılıkları
├── README.md            # Bu dosya
├── logs/                # Log dosyaları (otomatik oluşturulur)
│   ├── honeypot.log
│   ├── honeypot_events.jsonl
│   ├── alerts.jsonl
│   ├── commands.jsonl
│   └── ftp_uploads/     # FTP ile yüklenen dosyalar
├── captures/            # PCAP dosyaları
└── reports/             # Üretilen HTML/JSON raporlar
```

## 🔧 Modüller

### SSH Honeypot (`ssh_honeypot.py`)
- Paramiko ile gerçekçi SSH sunucu simülasyonu
- Sahte kimlik bilgileri ile saldırganı "içeri alarak" davranışını gözlemleme
- Etkileşimli sahte kabuk (fake shell) - `ls`, `cat`, `whoami`, `ps` vb. komutlara gerçekçi yanıtlar
- Sahte dosya sistemi (`/etc/passwd`, `notes.txt` vb.)
- Çalıştırılan her komutun ve her kimlik doğrulama denemesinin kaydı

### FTP Honeypot (`ftp_honeypot.py`)
- Socket tabanlı, sıfırdan kodlanmış FTP protokol simülasyonu
- Sahte dosya sistemi ile dizin gezintisi ve dosya indirme
- **Dosya yükleme tespiti** → yüklenen dosyalar SHA-256 ile hash'lenerek saklanır
- Zararlı yazılım yükleme anında alarm

### HTTP Honeypot (`http_honeypot.py`)
- Sahte admin login paneli, API endpoint'leri, `.env` dosyası
- **SQL Injection**, **XSS**, **path traversal**, **command injection** tespiti (regex)
- WordPress/phpMyAdmin tarama tespiti
- `robots.txt` tuzağı ile dizin keşfini yönlendirme

### PCAP Yakalama (`pcap_capture.py`)
- Scapy ile tüm honeypot portlarına gelen trafiğin PCAP kaydı
- Otomatik BPF filtresi oluşturma
- Dosya rotasyonu ve boyut limiti
- Wireshark/tcpdump ile uyumlu çıktı

### Erken Uyarı Motoru (`alert_engine.py`)
- **Kaba kuvvet tespiti**: Zaman penceresi içinde başarısız giriş eşiği
- **Port tarama tespiti**: Farklı port erişim sayısı eşiği
- **Zararlı yazılım yükleme**: Anında kritik alarm
- **Yetki yükseltme**: Tehlikeli komut anahtar kelime eşleşmesi
- **Web saldırı tespiti**: SQL injection, XSS, LFI/RFI desenleri
- IP bazlı izleme, tekrar alarm engelleme, eski veri temizleme

### Analiz ve Raporlama (`analyzer.py`)
- Tüm logların istatistiksel analizi
- En aktif saldırgan IP'ler, en çok denenen kullanıcı/şifre, tehlikeli komutlar
- Saldırı zaman çizelgesi
- Saatlik aktivite grafiği
- **HTML formatında detaylı erken uyarı raporu** (önerilerle birlikte)

### Web Dashboard (`dashboard.py`)
- Flask tabanlı gerçek zamanlı izleme paneli
- 5 saniyede bir otomatik yenileme
- Son alarmlar, olaylar, komutlar, en aktif IP'ler
- REST API endpoint'leri (`/api/stats`, `/api/alerts`, `/api/events` vb.)

## 🧪 VirtualBox İzole Ağ Kurulumu

### Ağ Topolojisi
```
┌─────────────────────────────────────────────────┐
│              VirtualBox Internal Network          │
│                  (honeynet)                       │
│                                                   │
│  ┌──────────┐    ┌──────────┐   ┌──────────┐    │
│  │ Honeypot │    │ Kali     │   │ Win/Lin  │    │
│  │ Server   │    │ Linux    │   │ Client   │    │
│  │ Ubuntu   │    │ Attacker │   │ (opsiyonl)│    │
│  │ .56.10   │    │ .56.100  │   │ .56.50   │    │
│  └──────────┘    └──────────┘   └──────────┘    │
│                                                   │
│            Subnet: 192.168.56.0/24               │
└─────────────────────────────────────────────────┘
```

### Adımlar

1. **VirtualBox'ta "Internal Network" oluşturun** (isim: `honeynet`)
2. **Honeypot VM (Ubuntu/Debian):**
   - Ağ → Internal Network → `honeynet`
   - IP: `192.168.56.10/24`
   - Bu projeyi kurup çalıştırın
3. **Kali Linux VM (Saldırgan):**
   - Ağ → Internal Network → `honeynet`
   - IP: `192.168.56.100/24`

## 🎯 Saldırı Simülasyonu (Kali Linux'tan)

### 1. Ağ Keşfi (Nmap)
```bash
# Agresif tarama
nmap -A -T4 192.168.56.10

# Tüm portlar
nmap -p- 192.168.56.10

# Servis versiyonu
nmap -sV -sC 192.168.56.10 -p 2222,2121,8080
```

### 2. SSH Kaba Kuvvet
```bash
# Hydra ile kaba kuvvet
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.10:2222

# Manuel SSH bağlantısı
ssh admin@192.168.56.10 -p 2222
```

### 3. FTP Saldırısı
```bash
# FTP bağlantısı
ftp 192.168.56.10 2121

# Dosya yükleme
ftp> put malware.exe
```

### 4. HTTP Saldırısı
```bash
# Dizin tarama
dirb http://192.168.56.10:8080

# SQL Injection denemesi
curl "http://192.168.56.10:8080/admin/login" -d "username=admin' OR 1=1--&password=test"

# .env dosyası keşfi
curl http://192.168.56.10:8080/.env
```

### 5. Metasploit ile Zafiyet İstismarı
```bash
msfconsole
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.56.10
set RPORT 2222
set USER_FILE /usr/share/wordlists/common_users.txt
set PASS_FILE /usr/share/wordlists/common_passwords.txt
run
```

## 📊 Rapor Üretimi

```bash
# Otomatik: Sistem her 5 dakikada otomatik rapor üretir
# Manuel:
python main.py --report
```

Rapor dosyaları `reports/` dizininde oluşturulur:
- `honeypot_report_XXXXXX.html` → Detaylı HTML rapor
- `honeypot_analysis_XXXXXX.json` → Ham analiz verisi (JSON)

## 📝 Log Formatları

### Olay Logu (`honeypot_events.jsonl`)
```json
{
  "event_id": 1,
  "timestamp": "2024-01-15T14:23:01.123456+00:00",
  "event_type": "auth_attempt",
  "service": "ssh",
  "src_ip": "192.168.56.100",
  "src_port": 45678,
  "details": {
    "username": "admin",
    "password": "password123",
    "attempt": 3,
    "method": "password"
  }
}
```

### Alarm Logu (`alerts.jsonl`)
```json
{
  "timestamp": "2024-01-15T14:23:05.789+00:00",
  "alert_type": "brute_force",
  "severity": "high",
  "src_ip": "192.168.56.100",
  "description": "SSH kaba kuvvet saldırısı: 5 başarısız deneme / 60s pencere",
  "evidence": {
    "service": "ssh",
    "attempts_in_window": 5,
    "threshold": 5
  }
}
```

## ⚠️ Güvenlik Uyarısı

Bu sistem **yalnızca eğitim ve araştırma amaçlı**, izole bir sanal ortamda kullanılmak üzere tasarlanmıştır. Gerçek üretim ağlarında doğrudan kullanılmamalıdır.
