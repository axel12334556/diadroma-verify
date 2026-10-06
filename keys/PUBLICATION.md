# Publier l'outil de clés (`diadroma-cles.html`)

Ce document décrit **comment** publier le fichier. Il ne le publie pas : rien n'est mis en ligne tant que les conditions ci-dessous ne sont pas remplies.

## Principe

L'outil crée les clés privées du client (il refuse d'ailleurs de créer, sauvegarder ou contrôler quoi que ce soit s'il est ouvert depuis un site web : seul le fichier ouvert depuis le disque fonctionne). Il est donc distribué comme **fichier à télécharger**, que le client ouvre depuis son disque (`file://`), et **jamais comme page web à utiliser en ligne** : une page servie par un site oblige à faire confiance au site à chaque ouverture, alors qu'un fichier dont l'empreinte est contrôlée ne dépend plus de l'hébergeur. Ce dossier n'est pas publié sur GitHub Pages et ne doit pas l'être.

## Conditions avant toute publication publique

- [ ] Revue de sécurité indépendante faite **sur ce fichier** (lot 4), ses constats traités.
- [ ] Versions de Safari, Firefox et du système relevées dans `TEST_NAVIGATEURS.md`.
- [ ] Essai avec une personne non technique (lot 4).
- [ ] Texte du `LISEZMOI-CLIENT.md` relu (et traduit si des clients non francophones sont prévus).

Avant ces conditions, le fichier ne se remet qu'à un client pilote précis, avec son empreinte, par un canal que l'opérateur maîtrise.

## Étapes de publication

1. Partir de `main`, CI verte. Reconstruire et contrôler : `node keys/build-app.js --check` (doit réussir : le fichier commité est exactement celui que produisent les sources).
2. Créer une version (release) du dépôt `diadroma-verify` portant un numéro de version, avec en pièces jointes `diadroma-cles.html` et `diadroma-cles.html.sha256`.
3. Recopier l'**empreinte SHA-256** sur un **second canal indépendant** de GitHub : la page de téléchargement de `www.diadroma.fr`. Les deux doivent être identiques ; si l'un des deux est piraté, la différence se voit.
4. Contrôler soi-même, depuis la version publiée et non depuis le dépôt local : télécharger le fichier, `shasum -a 256 -c diadroma-cles.html.sha256`, comparer avec la page du site.
5. Noter dans la version : numéro, date, empreinte, résultat de la revue.

Une nouvelle version = une nouvelle empreinte. L'ancienne reste téléchargeable, mais la page du site n'affiche que l'empreinte courante et dit laquelle est périmée.

## Ce que cette distribution ne garantit pas

- Un client qui ne compare pas l'empreinte n'est pas protégé contre un fichier remplacé : la consigne est écrite dans `LISEZMOI-CLIENT.md`, mais le contrôle reste la sienne.
- Une empreinte publiée par le même acteur que le fichier prouve que le fichier est celui qu'il a publié, pas qu'il est sans défaut : c'est le rôle de la revue indépendante.
- La signature du fichier (au-delà de l'empreinte) n'est pas prévue à ce stade.
