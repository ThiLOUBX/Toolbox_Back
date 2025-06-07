import requests
import json

def send_data_to_api(data):
    url = "http://example.com/api/scan-results"
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, json=data, headers=headers)
    return response.status_code, response.text

if __name__ == "__main__":
    # Lire les résultats du scan depuis le fichier
    with open('scan_results.json', 'r') as file:
        scan_results = json.load(file)

    # Envoyer les données à l'API
    status_code, response_text = send_data_to_api(scan_results)
    print(f"Réponse de l'API : Status {status_code}, Message: {response_text}")