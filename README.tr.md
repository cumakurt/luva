# Luva

**Luva**, endüstriyel kontrol ve SCADA ağları için **yalnızca dosyadan okuyan** (pasif) bir çevrimdışı analiz aracıdır. `.pcap`, `.pcapng` ve `.gz` ile sarılı yakalama dosyalarını işler; **canlı dinleme**, **paket enjeksiyonu** veya sahada aktif müdahale **yoktur**.

[English README →](README.md)

<p align="center">
  <img src="img/main.png" alt="Luva etkileşimli HTML raporu — Executive sekmesi, KPI kartları ve grafikler" width="900"/>
</p>

<p align="center"><em>Şekil: üretilen HTML raporunda Executive özeti (KPI’lara tıklayınca detay). Luva PCAP/PCAPNG’yi çevrimdışı analiz eder; CLI ayrıca JSON, CSV, GraphML ve isteğe bağlı iletişim haritası / NDJSON üretir.</em></p>

## Ne yapar?

| Alan | Yetenekler |
|------|------------|
| **Protokoller** | **On bir** yerleşik OT/ICS protokolü için **Scapy** tabanlı ayrıştırma (aşağıdaki tablo). |
| **Varlıklar** | Uç noktaları (IP, MAC) keşfeder; **cihaz rolü** (PLC, HMI, RTU, ağ geçidi, mühendislik istasyonu vb.) çıkarımı yapar; **açık portlar**, **ICS’e özel alanlar** (ör. Modbus unit ID, S7 rack/slot, DNP3 adres ipuçları), MAC **OUI** ile **üretici ipuçları**, iletişim ortakları, bayt/paket sayıları ve **heuristik risk skoru** ile okunabilir risk faktörleri üretir. |
| **Akışlar** | **Çift yönlü akışlar** (5-bölümlü anahtar benzeri) oluşturur, ICS çerçevelerini akışlara bağlar ve raporlama için istatistik toplar. |
| **Topoloji** | **Mantıksal ağ/hizmet grafiği** (varlıklar ve ilişkiler) kurar ve **GraphML** dışa aktarır (CLI varsayılanı **`topology` + UTC zaman damgası + `.graphml`**); **Gephi**, **yEd**, **NetworkX** ile uyumludur. |
| **Tespit** | YAML tabanlı **kural motoru** (Modbus, S7, DNP3 ve genel kurallar); olaylarda **önem derecesi** (INFO → CRITICAL) ve **kategori** (protokol, davranış, ağ, politika). İstatistiksel yardımcılar kod içi analizleri destekler. |
| **Raporlama** | **JSON** (tam yapısal rapor), **CSV** (varlıklar, akışlar, anomaliler, **denetim bulguları**), **HTML** (tek dosya özet panosu) ve yukarıdaki **GraphML**. **CLI** her çalıştırmada dosya adlarına **UTC zaman damgası** ekler; arka arkaya taramalar birbirinin üzerine yazmaz (aşağıdaki çıktı tablosu). |
| **Derin paket analizi** | **`statistics.deep_survey`**: yakalama süresi, port/DNS/HTTP özetleri, TLS tahminleri, **`cleartext_hints`**, **`ics_port_visibility`**, banner örnekleri, zaman çizelgesi ve **OT şifresiz veri** sezgisel tespitleri (aşağıdaki bölüm). |
| **Tehdit odaklı özetler** | **`statistics.threat_patterns`**: pasif ipuçları (ör. Modbus yazma akışları, S7 kritik işlem aileleri, uzaktan erişim portları, tarayıcı/kimlik dizesi benzeri kalıplar, ARP/yayın gürültüsü, tekrarlayan TCP yük parmak izleri, çok hedefli ICS erişim sırası) — JSON ve HTML’de **Threat patterns** sekmesi; **`audit_workbook`** ile çapraz referans. |
| **OT şifresiz maruziyet** | **Şifrelenmemiş endüstriyel yük** için paket düzeyinde sezgisel kontroller (Modbus, IEC-104, S7, DNP3, OPC UA HEL, EtherNet/IP, BACnet/IP, SNMP topluluk dizesi *maskelenmiş*, OT anahtar kelimeli HTTP, kayıtlı ICS TCP portları). Çıktı: **`deep_survey.cleartext_ot_sensitive`**; HTML **Network & cleartext** tablosu; **`pentest_insights`** ve denetim bulgusu **`CLEARTEXT_OT_PAYLOAD`**. Ayrıntılar: [Derin anket ve OT cleartext](#derin-paket-anketi-ve-ot-cleartext). |
| **Denetim ve kanıt** | JSON üst verisinde girdi dosyaları için **bütünlük özeti** (SHA-256); yapılandırılmış **`audit_workbook`** (bulgular, MITRE ipuçları, iyileştirme metni, pasif maruziyet indeksi); HTML’de **Audit & pentest** sekmesi ve **`audit_findings.csv`**. Ayrıntılar: [Denetim ve kanıt](#denetim-ve-kanıt). |
| **EKS ve Purdue** | **ICS/EKS bileşen taksonomisi** (sahadan kurumsal katmana), varlık başına **sezgisel EKS etiketleri**, **Purdue / ISA-95 seviye özeti**, **IEC 62443 conduit** notu ve **OT segmentasyon** ilkeleri — **`analysis_report.json`** içinde **`eks`** altında ve HTML **EKS & Purdue** sekmesinde. |
| **Güvenlik modeli** | **Passivity guard**: analiz yalnızca normal yakalama dosyalarına yönelir; canlı yakalama tasarımda desteklenmez. |
| **Gizlilik** | **`anonymize_ips`** ve **`mask_payload`** (`AnalysisConfig` ve CLI **`--anonymize-ips`** / **`--mask-payload`**); `mask_payload` ayrıca **`deep_survey`** içindeki OT cleartext örnek alanlarını (hex önizleme, HTTP alıntısı, SNMP maske metni) dışa aktarımda gizler. |

## CLI (`luva.py` veya `luva` komutu)

Depo kökünden:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python luva.py yakalama.pcapng
# veya kurulumdan sonra:
luva yakalama.pcapng
```

Birden fazla dosya tek çalıştırmada birleştirilir:

```bash
python luva.py a.pcap b.pcapng
```

Varsayılan: **tam** boru hattı, **on bir** yerleşik ayrıştırıcı, minimum önem **INFO**, çıktılar **`./reports/`**. Analiz sırasında **stdout**’a `[Luva] …` kısa aşama satırları (kurallar, paket geçişi, anomali, topoloji, GraphML yolu) yazılır; **paket sayacı** varsayılan olarak **stderr**’dedir. **`--quiet`** ile `[Luva]` satırları ve dışa aktarma bandı kapatılır. Önemli seçenekler:

| Seçenek | Açıklama |
|--------|----------|
| `-o`, `--output-dir` | Çıktı dizini (varsayılan: `reports`) |
| `--mode` | `full`, `anomaly-only`, `asset-only`, `topology-only` |
| `--min-severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--protocols` | Virgülle ayrılmış kısa adlar, örn. `modbus,s7` |
| `--custom-rules` | Ek YAML kural dizini |
| `--formats` | Virgülle ayrılmış çıktılar: `json`, `csv`, `html`, `communication-map`, `anomalies-ndjson` veya `all` (varsayılan) |
| `--chunk-size` | Girdi başına en fazla paket (`0` = tüm dosya; hızlı örnekleme için) |
| `--compare-baseline` | Önceki **tam JSON** raporunun yolu (ör. `analysis_report_20260115_083022.json`); yeni JSON’a `statistics.baseline_diff` ekler |
| `--anomaly-subset-pcap` | Anomali olaylarının işaret ettiği paketleri bu PCAP yoluna yazar |
| `--anonymize-ips` / `--mask-payload` | Paylaşılan raporlar için gizlilik |
| `--no-graph` | Topoloji GraphML dışa aktarımını atla |
| `--graph-path` | GraphML için temel yol; **UTC çalıştırma damgası** uzantıdan önce eklenir (diğer çıktılarla aynı ek) |
| `--no-progress` | stderr paket ilerlemesini kapat |
| `-q`, `--quiet` | stdout `[Luva] …` aşama satırlarını ve “Writing exports…” bandını kapat |
| `-v`, `--verbose` | INFO seviyesinde günlük |

Örnek:

```bash
luva yakalama.pcapng -o ./cikti --mode asset-only --protocols modbus --anonymize-ips
luva yakalama.pcapng --formats json,anomalies-ndjson --chunk-size 50000
```

Kural YAML doğrulama (her `*.yaml` içindeki kurallar ayrışıyorsa çıkış `0`; hata varsa sıfır dışı):

```bash
luva validate-rules /yol/kurallar
luva validate-rules luva/detection/rules
```

### Çıktı dosyaları (CLI varsayılanları)

Her CLI çalıştırması **`_YYYYMMDD_HHMMSS`** biçiminde **UTC** bir ek üretir (ör. `_20260403_153045`) ve bunu tüm dışa aktarım **taban adlarına** uzantıdan önce ekler. JSON içinde **`metadata.report_filename_suffix`** bu eki (boş değilse) tekrarlar.

| Çıktı | Açıklama |
|--------|-----------|
| `analysis_report_<UTC>.json` | Üst veri, özet, varlıklar, akışlar, topoloji, anomaliler, istatistikler — **`statistics.deep_survey`**, **`statistics.threat_patterns`**, **`statistics.event_timeline`**, isteğe bağlı **`statistics.baseline_diff`**, **`statistics.audit_workbook`**, **`statistics.pentest_insights`** |
| `assets_<UTC>.csv` | Varlık tablosu |
| `ot_assets_<UTC>.csv` | OT/ICS sınıflı varlıklar (ICS portları, ayrıştırıcı etiketleri, saha ipuçları, çıkarılan roller) |
| `flows_<UTC>.csv` | Akış tablosu |
| `anomalies_<UTC>.csv` | Tespit olayları tablosu |
| `audit_findings_<UTC>.csv` | Denetim çalışma kitabı satırları (kimlik, önem, MITRE, iyileştirme, standart referansları) |
| `anomalies_<UTC>.ndjson` | Satır başına bir JSON nesnesi (SIEM); `--formats` ile etkinleştirilir |
| `<dosya-kökü>_<UTC>.html` veya `analysis_report_<UTC>.html` | HTML rapor: **Executive** (tıklanabilir KPI detayı), **Protocols & exposure**, **OT & comms**, **Assessment**, **Inventory (EKS)**, **OT inventory**, **Audit & pentest**, **Threat patterns**, **Network & cleartext**, **ICS flows**, matris, **Anomalies**, **Diagnostics** |
| `communication_map_<UTC>.html` | **Etkileşimli OT iletişim haritası** (D3, paketlendiğinde `luva/output/static/`; yoksa jsDelivr CDN): rol, üretici, risk; **oturum başına protokol**, L4, paket/bayt, yazma işareti; ICS filtresi |
| `topology_<UTC>.graphml` | Harici araçlar için graf |

**Kütüphane / testler:** **`AnalysisConfig(report_filename_suffix="")`** (varsayılan) ile raporlayıcılar **eski sabit adları** kullanır (`analysis_report.json`, `assets.csv`, …).

## Analiz modları (CLI ve Python API)

CLI **`--mode`** bayrağı, `AnalysisConfig.mode` ile aynı değerleri kullanır:

- **`full`** — varlık, akış, topoloji, anomali  
- **`anomaly-only`** — topoloji/graf dışa aktarım yolu atlanır  
- **`asset-only`** — varlık odaklı; boru hattının izin verdiği yerde anomali kuralları atlanır  
- **`topology-only`** — topoloji odaklı yol  

## Desteklenen ICS / OT protokolleri

| Protokol | Kısa ad | Tipik portlar | OT’de rolü |
|----------|---------|---------------|------------|
| **Modbus/TCP** | `modbus` | 502 | PLC, HMI ve saha cihazları arasında register/coil okuma-yazma; endüstriyel Ethernet’te çok yaygın. |
| **S7comm** | `s7` | 102 | Siemens S7 oturumu ve periyodik veri; mühendislik ve PLC I/O. |
| **DNP3** | `dnp3` | 20000 | SCADA/istasyon tarzı mesajlaşma (seri DNP3’ün TCP uyarlaması). |
| **OPC UA** | `opcua` | 4840 | Etiket, alarm, metot ve tarihçe verisine istemci-sunucu (ve pub/sub) erişimi. |
| **EtherNet/IP** | `enip` | 44818 | CIP kapsüllemesi; Allen-Bradley / Rockwell tarzı I/O ve explicit mesajlar. |
| **IEC 60870-5-104** | `iec104` | 2404 | Enerji sistemleri telekontrolü (APCI/ASDU) üzerinden TCP. |
| **BACnet/IP** | `bacnet` | 47808 | Bina otomasyonu: nesneler, özellikler, alarm, zamanlama (UDP/TCP; BVLC + APDU alt kümesi). |
| **MQTT** | `mqtt` | 1883, 8883, 8884, 9001 | Hafif yayın-abone; IIoT ağ geçitleri ve bulut bağlantılı SCADA. |
| **SNMP** | `snmp` | 161, 162 | İzleme ve yönetim (Get/Set, trap); ağ ekipmanları ve gömülü cihazlar. |
| **Omron FINS** | `omron_fins` | 9600 | TCP/UDP üzerinden FINS çerçevesi (pasif alt küme). |
| **GE SRTP** | `ge_srtp` | 18245, 18246 | SRTP zarfı (pasif alt küme). |

**Varsayılan etkin kısa adlar** (aynı on biri): `modbus`, `s7`, `dnp3`, `opcua`, `enip`, `iec104`, `bacnet`, `mqtt`, `snmp`, `omron_fins`, `ge_srtp`. Kümelemek için **`--protocols`** kullanın.

Port kaydında PROFINET, Foundation Fieldbus HSE vb. yalnızca ipucu olarak yer alır; tabloda parser’ı olmayanlar ayrı ayrıştırılmaz.

## Özel kurallar

CLI’de **`--custom-rules /yol/dizin`**, kodda **`AnalysisConfig.custom_rules_dir`**. Dosyalar yerleşik şemaya uygun olmalıdır (`luva/detection/rules/*.yaml`). Özel kuralları dağıtmadan önce **`luva validate-rules DİZİN`** ile kontrol edin.

## Python API (kütüphane)

```python
from pathlib import Path
from luva.core.config import AnalysisConfig, AnalysisMode, utc_report_filename_suffix
from luva.core.pipeline import AnalysisPipeline

cfg = AnalysisConfig(
    input_files=[Path("yakalama.pcapng")],
    mode=AnalysisMode.FULL,
    export_formats=("json", "csv"),
    chunk_size=0,
    compare_baseline=None,
    anomaly_subset_pcap=None,
    report_filename_suffix=utc_report_filename_suffix(),  # isteğe bağlı: CLI ile aynı damgalı adlar
    quiet=False,  # True: run() sırasında [Luva] stdout satırlarını kapat
)
sonuc = AnalysisPipeline(cfg).run()
# sonuc.assets, sonuc.flows, sonuc.anomalies, sonuc.to_dict()
```

## Denetim ve kanıt

Çevrimdışı yakalamalarla çalışan **denetçi, sızma testi uzmanı ve güvenlik değerlendiricileri** için pasif analiz şu çıktıları üretir:

| Çıktı | Konum | Amaç |
|--------|--------|------|
| **Girdi bütünlüğü** | `metadata.input_evidence` | Dosya başına yol, ad, boyut, diskte **olduğu gibi** baytların **SHA-256** özeti (ör. `.pcap.gz` sıkıştırılmış hali üzerinden). `metadata.evidence_integrity_note`, **zincir-of-custody** için nasıl kullanılacağını ve kopya/arsiv sonrası yeniden özet önerisini açıklar. |
| **Denetim çalışma kitabı** | `statistics.audit_workbook` | Yapılandırılmış bulgular (`AUD-001` …), önem derecesi, kategori, özet, kanıt özeti, **MITRE ATT&CK** *eşleme ipuçları*, iyileştirme metni ve **IEC 62443 / NIST SP 800-82** tarzı referanslar; **pasif maruziyet indeksi** (0–100, ağırlıklı önemler — **CVSS değildir**); **ICS yazma** akış örnekleri; **kamu IPv4** varlıkları; **22 / 3389 / 5900** gözlenen varlıklar; `pentest_insights` ile çapraz referans. |
| **HTML** | **Audit & pentest** sekmesi | Özet tablolar: hash’ler, kapsam/sınırlamalar, bulgular ve yüzey örnekleri. |
| **CSV** | `audit_findings_<UTC>.csv` (CLI) veya `audit_findings.csv` (`report_filename_suffix` boşsa) | Çalışma kitabı bulgularının düz dışa aktarımı (diğer CSV’lerle birlikte). |

MITRE ve IEC/NIST referansları **pasif trafikten türetilen sezgisel etiketlerdir** — bunları kesin teknik veya uyumluluk açığı saymadan önce **mimari**, **envanter** ve **tehdit modeliniz** ile doğrulayın.

## Derin paket anketi ve OT cleartext

Boru hattı her çalıştırmada **`statistics.deep_survey`** üretir: yakalama süresi, benzersiz IP/MAC sayıları, TCP/UDP port özetleri (kayıt etiketleriyle), dakika bazlı zaman çizelgesi, DNS sorguları, HTTP `Host` başlıkları, **`cleartext_hints`** (SSH/FTP/telnet/SNMP/HTTP benzeri sayaçlar), **`banner_samples`**, **`tls`** sezgisel verileri ve **`ics_port_visibility`**.

**`cleartext_ot_sensitive`**, yük **TLS İstemci Selamı gibi görünmüyorsa** paket düzeyinde **sınırlı** (varsayılan en fazla **40** ayrıştırılmış örnek satır) **şifresiz OT trafiği** arar. Örnek kategoriler: **502 üzerinde Modbus TCP** (MBAP + fonksiyon kodu; yazma ailesi FC’ler daha yüksek önem), **IEC-104** APCI biçimli çerçeveler, **102 üzerinde S7** TPKT, **20000 üzerinde DNP3**, **4840 üzerinde OPC UA** `HEL`, **44818 üzerinde EtherNet/IP** oturum kaydı, **UDP 47808 BACnet/IP** BVLC, **SNMPv1/v2c** topluluk alanı (örnekte **maskelenmiş**), **OT ile ilgili anahtar kelimeler içeren HTTP**, kayıt defterindeki diğer **ICS TCP** portlarında **TLS dışı** uygulama yükü.

Her örnekte uç noktalar, kısa **özet** ve **kısaltılmış hex** veya metin alıntısı yer alır. **`hits_by_category`** eşleşen her paketi sayar; örnekler kategori ve akış anahtarına göre tekilleştirilir.

- **JSON**: `statistics.deep_survey.cleartext_ot_sensitive`
- **HTML**: **Network & cleartext** → *OT-sensitive cleartext (heuristic)*
- **`pentest_insights`**: pasif bulgu ve **`summary_counts.cleartext_ot_packet_hits`**
- **`audit_workbook`**: isabet veya örnek varken **`CLEARTEXT_OT_PAYLOAD`**

Paylaşılan raporlarda **`--mask-payload`** kullanarak `evidence_preview_hex`, `http_context_excerpt` ve `snmp_community_redacted` alanlarını kaldırın. Sonuçlar **sezgiseldir** (TCP parçalanması, tünel ve standart dışı portlar yanlış negatif/pozitif üretebilir); şüpheli satırları PCAP üzerinde doğrulayın.

## Gereksinimler

- **Python 3.10+**
- Bağımlılıklar: **Scapy**, **NetworkX**, **Rich**, **Typer**, **PyYAML**, **Jinja2**, **NumPy** (`pyproject.toml` içinde)

### Çok büyük yakalamalar (ör. çok GB / ~20 GB)

Luva paketleri diskten **akış** olarak okur (tüm dosyayı RAM’e almaz). Akış başına durum **sabit bellek** (Welford istatistikleri) ile tutulur; her paket boyutu veya aralık listesi saklanmaz. Zaman çizelgesi **dakika** kutuları kullanır; DNS/HTTP çeşitliliği sınırlanır. **Varsayılan olarak** (`AnalysisConfig` / ek boyut bayrağı olmadan CLI) dışa aktarılan akışlar, iletişim matrisi ve **`communication_graph`** kenarları **sınırlanmaz** (`max_flows_export`, `max_communication_matrix_ips`, `max_communication_graph_edges` için **`0`** = tam rapor). Daha küçük JSON/HTML/CSV için `AnalysisConfig` üzerinde pozitif sınırlar verin. Varsayılan olarak her **2M pakette** stderr’e ilerleme yazılır; aşama özetleri **`[Luva] …`** ile **stdout**’tadır (`quiet=True` ile kapatılır). **`.pcap.gz`** için geçici dosya kadar **disk** gerekir.

## Örnek yakalamalar

Örnek dosyalar `luva/sample/` altındadır. Birçok `.pcap` dosyası `git lfs pull` yapılmadan **Git LFS işaretçisi** olabilir; bazı `.pcapng` dosyaları doğrudan ikili veridir.

### Her protokol için küçük dış örnekler (`public_pcaps/`)

**Üçüncü taraf** küçük PCAP dosyaları (Wireshark SampleCaptures + [w3h/icsmaster](https://github.com/w3h/icsmaster)) **Modbus, S7, DNP3, OPC UA, EtherNet/IP ve IEC 104** trafiğini tek analizde birlikte doğrulamak için kullanılabilir; **BACnet, MQTT ve SNMP** ayrıştırıcılarını kendi yakalamalarınızla deneyebilirsiniz:

```bash
./public_pcaps/fetch_public_pcaps.sh   # isteğe bağlı: ağdan yeniden indir
python luva.py public_pcaps/*.pcap
```

Kaynak ve adresler [`public_pcaps/SOURCES.txt`](public_pcaps/SOURCES.txt) dosyasında.

## Geliştirme

```bash
pip install -e ".[dev]"
pytest luva/tests ot_baseline/tests
ruff check luva ot_baseline luva.py baseline.py
mypy luva
```

**CI:** [GitHub Actions](.github/workflows/ci.yml) — `main` / `master` için push ve PR’larda Python **3.10**, **3.12**, **3.13** üzerinde **pytest**, **ruff**, **mypy**.

**Katkı:** [`CONTRIBUTING.md`](CONTRIBUTING.md) · **Güvenlik:** [`SECURITY.md`](SECURITY.md)

### GitHub’da yayın için kontrol listesi

| Öğe | Konum |
|-----|--------|
| Lisans | [`LICENSE`](LICENSE) (`pyproject.toml` ile uyumlu) |
| Proje meta ve URL’ler | [`pyproject.toml`](pyproject.toml) |
| Yerel / derleme gürültüsü | [`.gitignore`](.gitignore) |
| Otomatik test ve lint | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| Katkı ve güvenlik | [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md) |
| README ekran görüntüsü | [`img/main.png`](img/main.png) |

## Geliştirici

**Cuma KURT** — [cumakurt@gmail.com](mailto:cumakurt@gmail.com)

- [LinkedIn](https://www.linkedin.com/in/cuma-kurt-34414917/)
- [GitHub deposu](https://github.com/cumakurt/luva)

## Lisans

Luva **GNU Affero Genel Kamu Lisansı sürüm 3.0 yalnızca** (**AGPL-3.0-only**) ile lisanslanmıştır. Metin için [`LICENSE`](LICENSE) dosyasına bakın. **Değiştirilmiş** bir sürümü **ağ hizmeti** olarak çalıştırıyorsanız, AGPL bu hizmetle etkileşen kullanıcılara ilgili kaynak kodun sunulmasını gerektirir.
