# BouncyCastle — reflectie-gevoelig, behouden
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# zxcvbn (password strength)
-keep class com.nulabinc.zxcvbn.** { *; }

# AndroidX Security (Tink onder de motorkap)
-keep class com.google.crypto.tink.** { *; }
-dontwarn com.google.crypto.tink.**

# ZXing embedded
-keep class com.journeyapps.** { *; }
-keep class com.google.zxing.** { *; }
