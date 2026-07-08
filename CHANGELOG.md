# Changelog

## [2.0.0] — herbouw

### Beveiliging (kritiek)
- **ChaCha20 → ChaCha20-Poly1305**: kale stream cipher vervangen door echte AEAD.
- **Bestandsversleuteling gerepareerd**: verwijderde de bug die bij het ontsleutelen een nieuwe random IV genereerde; het wachtwoord wordt nu daadwerkelijk gebruikt.
- **Geauthenticeerd container-formaat**: header (algoritme/salt/nonce) als AAD — geen stille manipulatie meer.
- **Argon2id** voor key-derivation (was PBKDF2).
- **Steganografie herschreven**: de oude implementatie verloor 7 van de 8 bits en had geen lengte-header; verbergt nu correct versleutelde containers.
- **Hardcoded `default_key` in de terminal verwijderd.**
- **Root-check**: `exec("su")`-hack vervangen door een niet-invasieve indicatie.
- Sleutels worden na gebruik uit het geheugen gewist; overal expliciet UTF-8.
- Legacy-hashes (MD5/SHA-1) standaard geweigerd.

### Project
- Volledig Gradle-project (was: losse bestanden zonder buildsysteem).
- UI gemigreerd naar **Jetpack Compose + Material 3** (Matrix-thema).
- `MANAGE_EXTERNAL_STORAGE` + brede storage-permissies verwijderd; SAF.
- Unit-tests voor de crypto + CI-workflow.
- Biometrische sleutelopslag via Keystore + EncryptedSharedPreferences.
