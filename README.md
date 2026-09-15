# SB AntiSpam & Captcha

Plugin WordPress anti-spam de StarBoost. Sans service externe, sans reCAPTCHA.

**Protections** : honeypot, jeton cookie, captcha mathématique signé (HMAC), listes noires d'emails/domaines, ~29 000 domaines jetables, journal.

**Formulaires couverts** : commentaires, inscription et connexion WordPress, WooCommerce (Mon compte, connexion, checkout shortcode), Contact Form 7, Elementor Pro Forms, Forminator, Ninja Forms.

## Installation
Télécharger `sb-antispam.zip` depuis la dernière release, l'installer via Extensions → Ajouter, puis régler dans Réglages → SB AntiSpam.

## Mises à jour
Les sites vérifient `info.json` toutes les 12 h et proposent la mise à jour dans Extensions.

## Publier une version
1. Incrémenter `Version:` et `const VERSION` dans `sb-antispam.php`
2. `./build.sh` (génère le zip et met à jour `info.json`)
3. Commit + push
4. Créer la release `vX.Y.Z` et **attacher `sb-antispam.zip`** (pas le zip auto-généré par GitHub)
