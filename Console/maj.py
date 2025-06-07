import subprocess
import platform

# Fonction pour vérifier et appliquer les mises à jour sur Windows
def update_windows():
    try:
        print("Vérification des mises à jour disponibles sur Windows...")
        subprocess.run(['winget', 'upgrade'], check=True)
        apply = input("Voulez-vous appliquer toutes les mises à jour ? (Oui/Non): ").strip().lower()
        if apply == 'oui':
            print("Application des mises à jour...")
            subprocess.run(['winget', 'upgrade', '--all'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Une erreur est survenue : {e}")

# Fonction pour vérifier et appliquer les mises à jour sur Linux
def update_linux():
    try:
        print("Vérification des mises à jour disponibles sur Linux...")
        subprocess.run(['sudo', 'apt-get', 'update'], check=True)
        apply = input("Voulez-vous appliquer toutes les mises à jour ? (Oui/Non): ").strip().lower()
        if apply == 'oui':
            print("Application des mises à jour...")
            subprocess.run(['sudo', 'apt-get', 'upgrade', '-y'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Une erreur est survenue : {e}")

