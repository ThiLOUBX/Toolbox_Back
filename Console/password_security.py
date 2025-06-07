from password_strength import PasswordPolicy
import os

# Définir la politique de mot de passe avec les critères souhaités
policy = PasswordPolicy.from_names(
    length=8,  # Longueur minimale : 8
    uppercase=2,  # Au moins 2 lettres majuscules
    numbers=2,  # Au moins 2 chiffres
    special=2,  # Au moins 2 caractères spéciaux
    nonletters=2,  # Au moins 2 caractères non-lettres
)

wordlist_path = './wordlist.txt'

def password_security_check(password):
    # Vérifier si le mot de passe est dans la wordlist
    try:
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                if password in (line.strip() for line in file):
                    return "Mot de passe faible : trouvé dans la liste des mots de passe communs."
    except UnicodeDecodeError:
        return "Erreur de lecture de la wordlist : le fichier contient des caractères non UTF-8."

    # Vérifier la politique de mot de passe
    errors = policy.test(password)

    # Vérifier les autres faiblesses
    if errors:
        error_messages = {
            'Length': "Mot de passe faible : trop court.",
            'Uppercase': "Mot de passe faible : doit contenir des lettres majuscules.",
            'Numbers': "Mot de passe faible : doit contenir des chiffres.",
            'Special': "Mot de passe faible : doit contenir des caractères spéciaux.",
            'Nonletters': "Mot de passe faible : doit contenir des caractères non-lettres.",
        }
        for error in errors:
            error_name = error.__class__.__name__
            if error_name in error_messages:
                return error_messages[error_name]
        return "Mot de passe faible."
    else:
        return "Mot de passe fort."
