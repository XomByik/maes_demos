# Demonštrácia funkčnosti režimov AES-u z knižnice micro-AES pomocou oficiálnych testovacích vektorov

## Obsah
1. [Základný prehľad](#základný-prehľad)
2. [Inštalácia](#inštalácia)
3. [Ako to funguje](#ako-to-funguje)
4. [Používanie programu](#používanie-programu)
5. [Technická dokumentácia](#technická-dokumentácia)
6. [Bezpečnostné informácie](#bezpečnostné-informácie)
7. [Podporované režimy](#podporované-režimy)

## Základný prehľad

Tento projekt obsahuje demonštračné implementácie rôznych režimov šifrovania AES. Je vhodný pre:
- Testovanie správnej implementácie AES režimov
- Overenie kompatibility s oficiálnymi testovacími vektormi
- Vzdelávacie účely

### Hlavné výhody
- Podporuje širokú škálu AES režimov (ECB, CBC, CTR, XTS, GCM, SIV a ďalšie)
- Podpora kľúčových veľkostí: 128, 192, a 256 bitov
- Kompatibilita s oficiálnymi NIST a inými testovacími vektormi
- Modulárna štruktúra umožňujúca jednoduché pridávanie ďalších režimov
- Čistá implementácia v C

### Spracovanie testovacích vektorov

1. **Jednotný formát parsovania**
   - Automatické rozpoznávanie formátov testovacích vektorov
   - Podpora rôznych formátov špecifických pre konkrétne režimy
   - Flexibilné rozpoznávanie kľúčových častí vektorov

2. **Vizualizácia výsledkov**
   - Prehľadný výpis vstupných parametrov
   - Zobrazenie očakávaných a vypočítaných hodnôt
   - Jasné vyhodnotenie úspešnosti testu

## Inštalácia

### Požiadavky
- Kompilátor GCC/Clang
- Make

### Kompilácia

1. Klonovanie repozitára:
```bash
git clone https://github.com/yourusername/maes_demos.git
cd maes_demos
```

2. Kompilácia programu:
```bash
make
```

3. Kompilácia konkrétneho režimu (napríklad AES-GCM s 256-bitovým kľúčom):
```bash
make gcm_256
```

## Ako to funguje

### Architektúra projektu

Projekt je organizovaný do nasledujúcej štruktúry:

```
maes_demos/
├── libs/
│   ├── micro_aes.c       # Hlavná implementácia AES
│   ├── micro_fpe.h       # Implementácia FPE režimu
│   └── ...
├── header_files/         # Hlavičkové súbory pre každý režim 
│   ├── cbc.h
│   ├── gcm.h
│   └── ...
├── src/                  # Demonštračné programy pre každý režim
│   ├── cbc_demo.c
│   ├── gcm_demo.c
│   └── ...
└── test_vectors/         # Testovacie vektory pre jednotlivé režimy
    ├── cbc_128.txt
    ├── gcm_256.txt
    └── ...
```

### Proces testovania

1. **Načítanie testovacích vektorov**:
   - Každý demonštračný program načíta testovacie vektory zo súboru
   - Vektory sú analyzované a rozdelené na relevantné časti (kľúč, IV, vstupné dáta, očakávané výstupy)
   
2. **Spustenie šifrovacieho algoritmu**:
   - Využívame knižničnú implementáciu pre daný režim z `micro_aes.c`
   - Volanie príslušných funkcií pre šifrovanie a dešifrovanie
   
3. **Porovnanie výsledkov**:
   - Porovnanie vypočítaných výsledkov s očakávanými výsledkami
   - Vyhodnotenie a zobrazenie výsledkov testu

## Používanie programu

### Kompilácia konkrétneho režimu

Pomocou Makefile môžete vytvoriť špecifickú verziu programu pre konkrétny režim a veľkosť kľúča:

```bash
# AES-ECB s 128-bitovým kľúčom
make ecb_128

# AES-CBC s 256-bitovým kľúčom
make cbc_256

# AES-GCM s 192-bitovým kľúčom
make gcm_192
```

### Spustenie testovania

```bash
# Pre AES-XTS s 128-bitovým kľúčom
./xts_128

# Pre AES-GCM-SIV s 256-bitovým kľúčom
./gcm_siv_256

# Pre AES-FPE-FF3 s 128-bitovým kľúčom
./ff3_128
```

### Príklad výstupu

```
AES-256 GCM Test
Pouziva sa testovaci subor: test_vectors/gcm_256.txt
=== Test #0 ===
Vstupne data:
  IV: 00000000000000000000000000000000
  AAD: (prazdne)
  Plaintext: 00000000000000000000000000000000
  Ocakavany ciphertext: cea7403d4d606b6e074ec5d3baf39d18
  Ocakavany tag: d0d1c8a799996bf0265b98b5d48ab919

Test sifrovania:
  Vypocitany ciphertext: cea7403d4d606b6e074ec5d3baf39d18
  Vypocitany tag: d0d1c8a799996bf0265b98b5d48ab919
  Vysledok: USPESNY

Test desifrovania:
  Vypocitany plaintext: 00000000000000000000000000000000
  Autentifikacia: USPESNA
  Vysledok: USPESNY
```

## Podporované režimy a testovacie vektory

Nasledujúca tabuľka zhŕňa podporované režimy AES spolu s relevantnými štandardmi, publikáciami a testovacími vektormi dostupnými v projekte:

| Režim    | 128-bit | 192-bit | 256-bit | Autentifikácia | Štandard/Zdroj testovacích vektorov | Testovacie vektory |
|----------|:-------:|:-------:|:-------:|:--------------:|----------------------|-------------------|
| ECB      | ✓       | ✓       | ✓       | ✗              | NIST SP 800-38A (2001)<br>[doi:10.6028/NIST.SP.800-38A](https://doi.org/10.6028/NIST.SP.800-38A) | `/test_vectors/ecb_128.txt`<br>`/test_vectors/ecb_192.txt`<br>`/test_vectors/ecb_256.txt` |
| CBC      | ✓       | ✓       | ✓       | ✗              | NIST SP 800-38A (2001)<br>[doi:10.6028/NIST.SP.800-38A](https://doi.org/10.6028/NIST.SP.800-38A) | `/test_vectors/cbc_128.txt`<br>`/test_vectors/cbc_192.txt`<br>`/test_vectors/cbc_256.txt` |
| CTR      | ✓       | ✓       | ✓       | ✗              | NIST SP 800-38A (2001)<br>[doi:10.6028/NIST.SP.800-38A](https://doi.org/10.6028/NIST.SP.800-38A) | `/test_vectors/ctr_128.txt`<br>`/test_vectors/ctr_192.txt`<br>`/test_vectors/ctr_256.txt` |
| CFB      | ✓       | ✓       | ✓       | ✗              | NIST SP 800-38A (2001)<br>[doi:10.6028/NIST.SP.800-38A](https://doi.org/10.6028/NIST.SP.800-38A) | `/test_vectors/cfb_128.txt`<br>`/test_vectors/cfb8_128.txt`<br>`/test_vectors/cfb1_128.txt` |
| OFB      | ✓       | ✓       | ✓       | ✗              | NIST SP 800-38A (2001)<br>[doi:10.6028/NIST.SP.800-38A](https://doi.org/10.6028/NIST.SP.800-38A) | `/test_vectors/ofb_128.txt`<br>`/test_vectors/ofb_192.txt`<br>`/test_vectors/ofb_256.txt` |
| XTS      | ✓       | ✗       | ✓       | ✗              | IEEE Std 1619-2018<br>[doi:10.1109/IEEESTD.2019.8637988](https://doi.org/10.1109/IEEESTD.2019.8637988) | `/test_vectors/xts_128.txt`<br>`/test_vectors/xts_256.txt` |
| GCM      | ✓       | ✓       | ✓       | ✓              | NIST SP 800-38D (2007)<br>[Cryptographic Algorithm Validation Program](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#GCMVS)  | `/test_vectors/gcm_128.txt`<br>`/test_vectors/gcm_192.txt`<br>`/test_vectors/gcm_256.txt`<br>`/test_vectors/gcm1024_128.txt` |
| CCM      | ✓       | ✓       | ✓       | ✓              | NIST SP 800-38C (2004)<br>[Cryptographic Algorithm Validation Program](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#CCM) | `/test_vectors/ccm_128.txt`<br>`/test_vectors/ccm_192.txt`<br>`/test_vectors/ccm_256.txt` |
| GCM-SIV  | ✓       | ✗       | ✓       | ✓              | RFC 8452 (2019)<br>[doi:10.17487/RFC8452](https://doi.org/10.17487/RFC8452) | `/test_vectors/gcm_siv_128.txt`<br>`/test_vectors/gcm_siv_256.txt` |
| SIV      | ✓       | ✗       | ✗       | ✓              | RFC 5297 (2008)<br>[doi:10.17487/RFC5297](https://doi.org/10.17487/RFC5297) | `/test_vectors/siv_128.txt`<br>`/test_vectors/siv_256.txt` |
| OCB      | ✓       | ✗       | ✗       | ✓              | RFC 7253 (2014)<br>[doi:10.17487/RFC7253](https://doi.org/10.17487/RFC7253) | `/test_vectors/ocb_128.txt`<br>`/test_vectors/ocb_192.txt`<br>`/test_vectors/ocb_256.txt` |
| EAX      | ✓       | ✗       | ✗       | ✓              | Bellare, M., Rogaway, P., Wagner, D. (2004)<br>The EAX Mode of Operation<br>[https://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf](https://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf) | `/test_vectors/eax_128.txt`<br>`/test_vectors/eax_192.txt`<br>`/test_vectors/eax_256.txt` |
| KW       | ✓       | ✓       | ✓       | ✓              | NIST SP 800-38F (2012)<br>[Cryptographic Algorithm Validation Program](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#KW) | `/test_vectors/kw_ae_128.txt`<br>`/test_vectors/kw_ad_128.txt`<br>`/test_vectors/kw_ae_256.txt` |
| FPE-FF1  | ✓       | ✓       | ✓       | ✗              | NIST SP 800-38G (2016)<br>[Block Cipher Modes of Operation - FF1 Method for Format-Preserving Encryption](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf) | `/test_vectors/ff1_128.txt`<br>`/test_vectors/ff1_192.txt`<br>`/test_vectors/ff1_256.txt` |
| FPE-FF3| ✓       | ✓       | ✓       | ✗              | NIST SP 800-38G (2016)<br>[Block Cipher Modes of Operation - FF3 Method for Format-Preserving Encryption](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF3samples.pdf   ) | `/test_vectors/ff3_128.txt`<br>`/test_vectors/ff3_192.txt`<br>`/test_vectors/ff3_256.txt` |