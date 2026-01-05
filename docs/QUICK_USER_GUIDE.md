# GhidraInsight - Kullanıcı Dostu Hızlı Rehber

**Tarih**: 5 Ocak 2026  
**Sürüm**: 1.0  
**Durum**: Üretim Hazır

---

## 🚀 Başlangıç (Sadece 3 Komut!)

### Option 1: Docker (En Kolay) ⭐
```bash
git clone https://github.com/ismailtsdln/GhidraInsight.git
cd GhidraInsight
docker-compose up -d && open http://localhost:3000
```

**Seçenekler**:
```bash
./scripts/startup.sh docker    # Başlat
./scripts/startup.sh stop      # Durdur
./scripts/troubleshoot.sh      # Sorun çöz
```

### Option 2: Otomatik Kurulum (macOS/Linux)
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh --mode=all
./scripts/startup.sh all
```

### Option 3: Sadece Python
```bash
pip install ghidrainsight
ghidrainsight analyze --file binary.elf
```

---

## 🎯 Yaygın Görevler

### 📊 Binary Analizi Yapmak

**Web Dashboard ile** (Önerilen):
```
1. http://localhost:3000 açın
2. Dosyayı sürükleyin
3. Sonuçları görüntüleyin
4. AI chat ile sorulan yanıtlayın
```

**CLI ile**:
```bash
ghidrainsight analyze --file binary.elf --output report.json
```

**Python SDK ile**:
```python
from ghidrainsight.client import GhidraInsightClient
client = GhidraInsightClient("http://localhost:8000")
results = await client.analyze("/path/to/binary")
```

---

### 🤖 AI Chat Kullanmak

#### Claude ile
```bash
# 1. Claude Desktop'ı açın
# 2. Settings → Preferences → Data Sources
# 3. GhidraInsight sunucusunu ekleyin: http://localhost:8000

# Veya CLI ile:
ghidrainsight integrate --provider claude --api-key $ANTHROPIC_API_KEY
```

#### ChatGPT ile
```bash
ghidrainsight integrate --provider openai --api-key $OPENAI_API_KEY
# GPT'de binary analizi yapabilirsiniz
```

---

### 🔍 Belirli Şeyler Bulma

**Crypto Algoritmaları**:
```bash
ghidrainsight analyze --file binary.elf --features crypto --verbose
```

**Güvenlik Açıkları**:
```bash
ghidrainsight analyze --file binary.elf --features vulnerabilities
```

**Data Flow Analizi**:
```bash
ghidrainsight taint --file binary.elf --source user_input --sink system_call
```

---

## 🛠️ Yapılandırma

### Temel Yapılandırma
```bash
# Etkileşimli kurulum
ghidrainsight config setup --guided

# Konfigürasyonu görün
ghidrainsight config list

# Değer değiştirin
ghidrainsight config set api.port 9000
```

### .env Dosyası (Opsiyonel)
```bash
# .env oluşturun ve yapılandırın
GHIDRA_SERVER_HOST=0.0.0.0
GHIDRA_SERVER_PORT=8000
GHIDRA_JWT_SECRET=your-secret-key
```

---

## 🆘 Sorun Çözme

### Hızlı Tanılama
```bash
./scripts/troubleshoot.sh        # İnteraktif mod
./scripts/troubleshoot.sh --full # Tam teşekküllü tanılama
```

### Yaygın Sorunlar

**"Docker not found"**
```bash
# Çözüm: Docker Desktop'ı indirin ve kurun
# https://www.docker.com/products/docker-desktop
```

**"Port 3000 already in use"**
```bash
# Çözüm: Varolan süreci durdurun
lsof -ti:3000 | xargs kill -9
```

**"Python module not found"**
```bash
# Çözüm:
pip install --upgrade ghidrainsight
```

**"Connection refused"**
```bash
# Sunucu çalışıyor mu kontrol edin:
docker-compose ps
# Sunucu loglarını görüntüleyin:
docker-compose logs python-mcp
```

---

## 📚 Belgeler

| Belge | İçerik | Kimler İçin |
|-------|--------|-----------|
| [README.md](../README.md) | Genel Bakış | Tüm Kullanıcılar |
| [EASE_OF_USE_IMPROVEMENTS.md](EASE_OF_USE_IMPROVEMENTS.md) | UX Geliştirmeleri | Geliştiriciler |
| [INSTALLATION.md](INSTALLATION.md) | Kurulum Detayları | Geliştiriciler |
| [SECURITY.md](SECURITY.md) | Güvenlik Rehberi | DevOps |
| [API_REFERENCE.md](API_REFERENCE.md) | API Dökümantasyonu | Entegratörler |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Kod Katkısı | Geliştiriciler |

---

## 🔗 Hızlı Linkler

**Başlatma Scriptleri**:
- `./scripts/setup.sh` - Kurulum (İlk kez)
- `./scripts/startup.sh` - Başlat
- `./scripts/troubleshoot.sh` - Sorun çöz

**CLI Komutları**:
```bash
ghidrainsight --version          # Versiyon
ghidrainsight --help             # Yardım
ghidrainsight analyze --help     # Analiz yardımı
ghidrainsight config --help      # Yapılandırma yardımı
```

**Web Arayüzleri**:
- 🌐 Dashboard: http://localhost:3000
- 🔌 API: http://localhost:8000
- 📡 WebSocket: ws://localhost:8001

---

## 💡 İpuçları ve Püf Noktaları

### 1. Docker Hızlı Komutları
```bash
# Günlükleri görün
docker-compose logs -f

# Belirli servisin günlüğünü görün
docker-compose logs -f python-mcp

# Komut satırı alın
docker-compose exec python-mcp bash

# Yapılandırma dosyasını düzenleyin
nano docker-compose.yml
```

### 2. CLI Otomatik Tamamlama
```bash
# Bash (macOS/Linux)
eval "$(ghidrainsight --bash-complete)"

# Zsh
eval "$(ghidrainsight --zsh-complete)"
```

### 3. Toplu Analiz
```bash
# Bir klasördeki tüm dosyaları analiz et
for file in binaries/*; do
    ghidrainsight analyze --file "$file" --output "results/$(basename $file).json"
done
```

### 4. CI/CD Entegrasyonu
```yaml
# .github/workflows/security-check.yml
name: Security Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Analyze Binaries
        run: |
          pip install ghidrainsight
          ghidrainsight analyze --file ./binary --strict
```

### 5. Özel Sonlandırıcı Yazma
```python
# custom_analyzer.py
from ghidrainsight.client import GhidraInsightClient
import asyncio

async def custom_analysis(binary_path):
    client = GhidraInsightClient()
    
    # Standart analiz
    results = await client.analyze(binary_path)
    
    # Özel işleme
    for vuln in results.vulnerabilities:
        if vuln.severity == "CRITICAL":
            print(f"🔴 {vuln.name}: {vuln.description}")
    
    return results

asyncio.run(custom_analysis("./binary.elf"))
```

---

## 🎓 Öğrenme Kaynakları

### Başlayanlar İçin
1. **5 Dakikalık Hızlı Başlangıç**
   - `cat docs/QUICKSTART.md`
   - İlk analizinizi yapın

2. **10 Dakikalık Dashboard Turuna**
   - http://localhost:3000 açın
   - Örnek dosya yükleyin (gelecek yakında)
   - Özellikleri keşfedin

3. **CLI Öğretimi**
   ```bash
   ghidrainsight analyze --help
   ghidrainsight taint --help
   ```

### Orta Seviye
- [API_REFERENCE.md](API_REFERENCE.md) - REST API
- [ARCHITECTURE.md](ARCHITECTURE.md) - Sistem tasarımı
- Integration Rehberleri (Claude, OpenAI, MCP)

### İleri Seviye
- Özel analyzer yazma
- Docker compose özelleştirme
- Production deployment

---

## 📞 Yardım Almak

### Sık Sorulan Sorular
```bash
# Güncellemeleri kontrol et
ghidrainsight update check

# Sistem bilgisi topla (rapor göndermek için)
./scripts/troubleshoot.sh --full
```

### İletişim Kanalları
- 💬 [Discussions](https://github.com/ismailtsdln/GhidraInsight/discussions)
- 🐛 [Issues](https://github.com/ismailtsdln/GhidraInsight/issues)
- 📧 Email: support@ghidrainsight.dev

---

## ✨ Faydalı Kaynaklar

- [Ghidra Resmi Sitesi](https://ghidra-sre.org/)
- [Ghidra Dokümantasyonu](https://ghidra-sre.org/releaseNotes)
- [MCP Protokolü](https://modelcontextprotocol.org/)
- [Python Async Rehberi](https://docs.python.org/3/library/asyncio.html)

---

## 🎉 Sonraki Adımlar

1. ✅ Kurulum yapın: `./scripts/setup.sh --mode=all`
2. 🚀 Başlatın: `./scripts/startup.sh docker`
3. 🌐 Dashboard açın: http://localhost:3000
4. 📊 İlk analizinizi yapın
5. 🤖 Claude/ChatGPT entegrasyonunu deneyin
6. 📖 Belgeleri okuyun
7. 💬 Geri bildirim gönderin

---

**Başarılı analizler! 🔍**

*Son güncellenme: 5 Ocak 2026*
