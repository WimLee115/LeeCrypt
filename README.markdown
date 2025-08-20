                                                 LeeCrypt



English

Overview

Lee Crypt, crafted by WimLee115, is a state-of-the-art Android app for text/file encryption, decryption, and hashing, wrapped in a Matrix-inspired hacker aesthetic. With AES-256-GCM, ChaCha20-Poly1305, and a full suite of hashes (MD5 to BLAKE3), it’s built for privacy fanatics. Features include biometric key storage, steganography, NFC/QR sharing, and a fake terminal mode. Fully offline, no tracking, Play Store-compliant. Greetings to PrivacyVerzetNL for championing digital freedom!

Key Features:





Encryption/Decryption: AES-256-GCM/ChaCha20-Poly1305 with PBKDF2 (200,000 iterations, SHA-512).



Hashing: MD5, SHA-1/256/512, HMAC-SHA512, BCrypt, SCrypt, Argon2, BLAKE3.



Key Management: Android Keystore with biometrics, NFC/QR sharing, real-time strength meter.



UI: Tabbed interface (Text, File, Terminal), Matrix animations, Hack font, theme switcher.



Security: Anti-tampering, root detection, encrypted SQLite logs, ProGuard obfuscation.



Extras: File encryption (≤10MB), steganography (PNG), auto-backup, clipboard monitoring.



Compliance: Min SDK 23, target SDK 34. Minimal perms (camera, storage, NFC optional).

Installation





Clone: git clone https://github.com/WimLee115/LeeCrypt.git



Open in Android Studio (Koala+).



Add dependencies (see build.gradle).



Download "Hack" font, place in res/font.



Build/run on emulator (Android 13+) or device.



For Play Store: Generate signed AAB, upload with privacy policy.

Usage





Text Tab: Encrypt/decrypt text, hash, or hide in images. Use QR/NFC for keys.



File Tab: Encrypt/decrypt files (≤10MB) with progress bar.



Terminal Tab: Run commands like encrypt -f <text>, hash -t BLAKE3 <text>.



Settings: Switch themes (Matrix Green, Cyberpunk Neon, Dark Void).



Security: Save keys with biometrics, monitor clipboard, enable logs.

Security Notes (Red/Blue Team Insights):





Use keys with zxcvbn score >3. Store in password manager.



Avoid MD5/SHA-1 for sensitive data; prefer Argon2/BLAKE3.



Test with MobSF and drozer on Kali for vulnerabilities.



Rooted devices are flagged—avoid for critical operations.



Steganography is experimental; verify extracted data.

Dependencies





BouncyCastle: Crypto (AES, ChaCha, BLAKE3).



ZXing: QR scanning.



zxcvbn: Key strength.



AndroidX: Biometrics, Keystore, ViewPager2.



SQLDelight: Encrypted logging.



Glide: Image processing.

Debugging





Logs: adb logcat | grep LeeCrypt.



Security: Run MobSF or drozer on Kali.



Memory: adb shell dumpsys meminfo com.wimlee115.leecrypt.

License

MIT License. By WimLee115. Educational use only—stay legal.

Greetings to PrivacyVerzetNL—keep fighting for privacy!



Nederlands

Overzicht

LeeCrypt, gebouwd door WimLee115, is een ultramoderne Android app voor tekst/bestandsversleuteling, ontsleuteling en hashing, verpakt in een Matrix-geïnspireerde hacker look. Met AES-256-GCM, ChaCha20-Poly1305 en hashes van MD5 tot BLAKE3 is het gemaakt voor privacy freaks. Features omvatten biometrische sleutelopslag, steganografie, NFC/QR sharing en een fake terminal mode. Volledig offline, geen tracking, Play Store-compliant. Groetjes aan PrivacyVerzetNL voor hun strijd voor digitale vrijheid!

Belangrijke Functies:





Versleuteling/Ontsleuteling: AES-256-GCM/ChaCha20-Poly1305 met PBKDF2 (200,000 iteraties, SHA-512).



Hashing: MD5, SHA-1/256/512, HMAC-SHA512, BCrypt, SCrypt, Argon2, BLAKE3.



Sleutelbeheer: Android Keystore met biometrie, NFC/QR sharing, real-time sterkte meter.



UI: Tabbed interface (Tekst, Bestand, Terminal), Matrix animaties, Hack font, thema switcher.



Beveiliging: Anti-tampering, root detectie, versleutelde SQLite logs, ProGuard obfuscation.



Extra’s: Bestandsversleuteling (≤10MB), steganografie (PNG), auto-backup, klembord monitoring.



Compliance: Min SDK 23, target SDK 34. Minimale perms (camera, storage, NFC optioneel).

Installatie





Kloont: git clone https://github.com/WimLee115/LeeCrypt.git



Open in Android Studio (Koala+).



Voeg dependencies toe (zie build.gradle).



Download "Hack" font, plaats in res/font.



Bouw/run op emulator (Android 13+) of toestel.



Voor Play Store: Genereer signed AAB, upload met privacybeleid.

Gebruik





Tekst Tab: Versleutel/ontsleutel tekst, hash, of verberg in afbeeldingen. Gebruik QR/NFC voor sleutels.



Bestand Tab: Versleutel/ontsleutel bestanden (≤10MB) met progress bar.



Terminal Tab: Voer commando’s uit zoals encrypt -f <tekst>, hash -t BLAKE3 <tekst>.



Instellingen: Wissel thema’s (Matrix Green, Cyberpunk Neon, Dark Void).



Beveiliging: Sla sleutels op met biometrie, monitor klembord, activeer logs.

Beveiligingsnotities (Red/Blue Team Inzichten):





Gebruik sleutels met zxcvbn score >3. Bewaar in password manager.



Vermijd MD5/SHA-1 voor gevoelige data; kies Argon2/BLAKE3.



Test met MobSF en drozer op Kali voor kwetsbaarheden.



Geroodde toestellen worden gemarkeerd—vermijd voor kritieke operaties.



Steganografie is experimenteel; verifieer geëxtraheerde data.

Afhankelijkheden





BouncyCastle: Crypto (AES, ChaCha, BLAKE3).



ZXing: QR-scanning.



zxcvbn: Sleutelsterkte.



AndroidX: Biometrie, Keystore, ViewPager2.



SQLDelight: Versleutelde logging.



Glide: Afbeeldingsverwerking.

Debugging





Logs: adb logcat | grep LeeCrypt.



Beveiliging: Run MobSF of drozer op Kali.



Geheugen: adb shell dumpsys meminfo com.wimlee115.leecrypt.

Licentie

MIT Licentie. Door WimLee115. Alleen educatief gebruik—blijf legaal.

Groetjes aan PrivacyVerzetNL—blijf vechten voor privacy!
