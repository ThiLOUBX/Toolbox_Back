# TOOLBOX
### Présentation du projet
Notre projet est conçu pour analyser et simuler  des cyberattaques à l'aide d'une API fournissant une vaste collection d'outils de cyberattaque spécifique à un Active Directory. Ce projet vise à offrir une plateforme permettant de mieux comprendre et évaluer les différentes techniques d'intrusion utilisées par les attaquants dans le but de renforcer la sécurité des systèmes.


### commande pour lancer le serveur en mode au moment de la dev 

```
 flask run --host=0.0.0.0 --port=5000 --debug
```

### Command pour la prod : 
``` 
screen -S bend gunicorn --bind 0.0.0.0:5000 main:app --log-level debug
```
