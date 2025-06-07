import subprocess
from flask import jsonify, request

# LDAPDomainDump for extracting AD information

def ldap_dump(domain_controller, output_dir):
    try:
        command = ['ldapdomaindump', '-o', output_dir, domain_controller]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        return jsonify({'status': 200, 'result': output})
    except Exception as e:
        return jsonify({'status': 500, 'error': str(e)})
