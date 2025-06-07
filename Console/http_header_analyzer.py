import requests
import os

def http_header_analyzer(url):
    log_file='headers.log'
    try:
        with open(log_file, 'w') as file:
            response = requests.get(url)
            headers = response.headers

            # Écrit les en-têtes dans le fichier log
            for key, value in headers.items():
                file.write(f"{key}: {value}\n")

            print(f"Les en-têtes ont été écrits dans le fichier {log_file}")

        return {'informations':headers}

    except requests.RequestException as e:
        result_message = f"Erreur: {e}"
        with open(log_file, 'w') as file:
            file.write(result_message)
        return result_message
