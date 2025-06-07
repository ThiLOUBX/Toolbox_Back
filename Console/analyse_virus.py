import requests
import os
import threading
from tkinterdnd2 import DND_FILES, TkinterDnD
import time

API_KEY = 'TOKEN VIRUS SCAN'

def scan_file(api_key, file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    with open(file_path, 'rb') as file:
        files = {'file': (os.path.basename(file_path), file)}
        params = {'apikey': api_key}
        response = requests.post(url, files=files, params=params)
    return response.json()

def get_report(api_key, resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': resource}
    response = requests.get(url, params=params)
    return response.json()

def process_file(file_path):
    if file_path:
        status_label.config(text="Scanning file, please wait...")
        progress_bar.start()
        scan_result = scan_file(API_KEY, file_path)
        if scan_result.get('response_code') == 1:
            resource_id = scan_result['resource']
            status_label.config(text=f"File queued for scanning, resource ID: {resource_id}")
            time.sleep(5)  # Wait for the report to be ready
            report_result = get_report(API_KEY, resource_id)
            detections = report_result.get('positives', 0)
            total = report_result.get('total', 0)
            if detections > 0:
                messagebox.showwarning("Detection Alert", f"Detections found: {detections}/{total}")
            else:
                messagebox.showinfo("Scan Result", "No detections found.")
        else:
            messagebox.showerror("Error", "Problem submitting the file for scanning.")
        progress_bar.stop()
    else:
        status_label.config(text="No file selected.")

def upload_action():
    file_path = filedialog.askopenfilename()
    threading.Thread(target=process_file, args=(file_path,), daemon=True).start()

def drop(event):
    file_path = event.data
    threading.Thread(target=process_file, args=(file_path,), daemon=True).start()

