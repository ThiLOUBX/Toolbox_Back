import subprocess
from flask import jsonify, request

# Kerbrute is used for brute-forcing Kerberos

def kerbrute_scan(domain, username_list):
    try:
        command = ['kerbrute', 'userenum', '-d', domain, username_list]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        return jsonify({'status': 200, 'result': output})
    except Exception as e:
        return jsonify({'status': 500, 'error': str(e)})
