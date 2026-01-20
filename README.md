# 🔴 DISCORD TOKEN CHECKER - Profesyonel Dashboard

**Glassmorphism kullanıcı arayüzü**, **WebSockets** üzerinden gerçek zamanlı izleme ve güçlü bir **Çok Kullanıcılı Yönetim Sistemi** içeren profesyonel düzeyde, yüksek performanslı bir Discord Token Checker.

![Dashboard Banner](https://via.placeholder.com/1200x400?text=Premium+Token+Checker+Panel+Dashboard)

---

## 🚀 Genel Bakış

**DISCORD TOKEN CHECKER**, basit bir betikten daha fazlasını isteyen kullanıcılar için tasarlanmıştır. Discord token kontrolünü yönetilen bir hizmete dönüştürür. Merkezi bir admin paneli ile aracı kimin ne kadar süreyle kullanacağını kontrol edebilir ve sistem performansını gerçek zamanlı olarak izleyebilirsiniz.

### 💎 Temel Özellikler
- **Modern Estetik**: Koyu kırmızı "Hacker" teması, üst düzey glassmorphism efektleri ve zarif mikro animasyonlar ile tasarlandı.
- **Asenkron İşleme**: Kontrol işlemleri arka plan iş parçacıklarında (threads) çalışır, böylece arayüz asla donmaz.
- **Soket Tabanlı**: Loglar ve istatistikler, sayfa yenilemeye gerek kalmadan anlık olarak istemciye iletilir.
- **Ölçeklenebilir Savunma**: Hız sınırlarını (rate limits) aşmak için entegre proxy desteği.

---

## ✨ Özellik Detayları

### 🛡️ Admin Yönetim Sistemi
Uygulamanın kalbi. Admin Paneli (`/admin`), tüm platformu koordine etmenizi sağlar:
- **Dinamik Kullanıcı Oluşturma**: Sınırlı veya ömür boyu erişime sahip kullanıcıları anında oluşturun.
- **Erişim Anahtarı Mantığı**: Oluşturulan erişim anahtarı, ikincil bir şifre görevi görerek yüksek düzeyde giriş güvenliği sağlar.
- **Üyelik Kontrolü**: Tek bir tıklamayla kullanıcıları engelleyin veya hesaplarını silin.
- **Güvenlik Merkezi**: Admin şifrenizi, güvenli hashing (PBKDF2) kullanarak doğrudan arayüzden güncelleyin.

### 📊 Gerçek Zamanlı Analizler
- **Canlı İstatistik Sayaçları**: Toplam, Geçerli, Geçersiz ve Nitro hitleri için animasyonlu sayaçlar.
- **Dinamik Sistem Logu**: Yanıt türlerini (`[VALID]`, `[INVALID]`, `[ERROR]`) kategorize eden yüksek hızlı konsol penceresi.
- **Görsel Geri Bildirim**: Gerçek zamanlı bağlantı durumu göstergesi.

### 🧪 Gelişmiş Checker Mantığı
- **Nitro Tespiti**: Nitro aboneliği olan tokenları otomatik olarak tanımlar ve işaretler.
- **Akıllı Gecikmeler**: Tespit edilmemek için istekler arasında kullanıcı tarafından tanımlanabilen gecikme süresi.
- **Çoklu Proxy Desteği**: Çeşitli proxy formatlarını destekler (IP:Port, Kullanıcı:Şifre@IP:Port).

---

## 🛠️ Teknik Mimari

### Teknoloji Yığını
| Katman | Teknoloji |
| :--- | :--- |
| **Backend** | Python 3.x, Flask |
| **Real-time Engine** | Flask-SocketIO (WebSockets) |
| **Veritabanı** | SQLite (SQLAlchemy ORM) |
| **Stil** | Vanilla CSS3 (Özel Değişkenler, Flexbox, Grid) |
| **Frontend Mantığı** | Vanilla JavaScript |

### 🗄️ Veritabanı Şeması (User Modeli)
Uygulama, aşağıdaki `User` yapısına sahip ilişkisel bir SQLite veritabanı kullanır:
- `id`: Benzersiz Kimlik (Primary Key)
- `username`: Giriş için benzersiz kullanıcı adı.
- `password`: Hashlenmiş kimlik bilgisi (PBKDF2-SHA256).
- `is_admin`: Yönetici ayrıcalıkları için boolean bayrağı.
- `is_banned`: Sistem erişimini kısıtlamak için boolean bayrağı.
- `access_key`: Kullanıcı kimlik doğrulaması için kullanılan benzersiz hex anahtarı.
- `expiry_date`: Üyelik sona erme süresi için DateTime nesnesi.

---

## 📥 Başlarken

### Gereksinimler
- Python 3.8 veya üzeri
- Pip (Python Paket Yöneticisi)

### Kurulum Adımları

1. **Klonlayın ve Klasöre Girin**:
   ```bash
   git clone https://github.com/thechecker45/discord-token-checker-web.git
   cd WebDashboard
   ```

2. **Sanal Ortam Kurulumu**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   ```

3. **Bağımlılıkları Yükleyin**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Sistemi Başlatın**:
   ```bash
   python app.py
   ```

---

## 📖 API Dokümantasyonu (Dahili)

| Uç Nokta | Metot | Açıklama |
| :--- | :--- | :--- |
| `/login` | GET/POST | Kullanıcı kimlik doğrulamasını yönetir. |
| `/admin` | GET | Yönetici panelini görüntüler. |
| `/api/start_check` | POST | Arka planda token kontrol sürecini başlatır. |
| `/api/stop` | POST | Tüm çalışanlara genel durdurma sinyali gönderir. |
| `/socket.io/` | WSS | Gerçek zamanlı loglar için WebSocket bağlantısı. |

---

## 🔐 Güvenlik Yapılandırması

### İlk Admin Kurulumu
İlk başlatmada, veritabanı otomatik olarak `/instance/database.db` konumunda oluşturulur.
- **Admin URL**: `http://localhost:5000/admin`
- **Kullanıcı**: `admin`
- **Varsayılan Şifre**: `admin123`

> [!CAUTION]
> **Kimlik Bilgilerini Değiştirin**: İlk girişinizden sonra, Admin Panelindeki "Update Admin" bölümüne gidin ve güçlü, benzersiz bir şifre belirleyin.

---

## 🛠 Sorun Giderme

- **Veritabanı Hataları**: Şema uyumsuzluklarıyla karşılaşırsanız, `/instance/database.db` dosyasını silin ve uygulamayı yeniden başlatın.
- **Port Çakışması**: `5000` portu kullanımdayda, `app.py` dosyasının son satırını değiştirin: `socketio.run(app, port=XXXX)`.
- **Proxy Sorunları**: Proxy listenizin `host:port` veya `user:pass@host:port` formatında olduğundan emin olun.

---

## 📜 Sorumluluk Reddi ve Lisans

**Sadece Eğitim Amaçlıdır**: Bu araç, güvenlik araştırması ve kendi hesaplarınızı test etmek için tasarlanmıştır. Geliştiriciler herhangi bir kötüye kullanımdan sorumlu değildir.

---
*Hız ve tasarım odaklı olarak geliştirildi*

---
**Developed By TheChecker** | [TheChecker Webpage](https://guns.lol/thechecker)
