from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_restful import Api, Resource
import secrets
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_jwt_extended import JWTManager , create_access_token , jwt_required , get_jwt_identity
from flask_socketio import SocketIO , emit
from datetime import timedelta
from flask_cors import CORS
from urllib.parse import quote_plus
from decouple import config
import decouple
import paramiko
import time
import psutil
import re
import subprocess
import socket
from Console.analyse_virus import scan_file , get_report ,process_file ,upload_action , drop 
from Console.http_header_analyzer import http_header_analyzer 
from Console.password_security import  password_security_check 
from Console.port_scanner import is_valid_ip , nmap_port_scan
from MSPR.SeahawksHarvester import choose_interface , get_network_info , scan_network , get_ip_range
#from flask_uploads import UploadSet , configure_uploads , ALL
#from werkzeug import secure_filename, FileStorage
#from  scan_vunerability import scan_ports 
app = Flask(__name__)
CORS(app)
#file = UploadSet('files',All)
#configure_uploads(app,files)

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://mspr:{config("DATABASE_PASSWORD")}@127.0.0.1/mspr'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = config('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=12)

socketio = SocketIO(app)
jwt = JWTManager(app)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
api = Api(app)

login_manager = LoginManager(app)
#Fonctionne de scan 
def scan_ports(host,start_port,end_port):
   open_port = []
   for port in range(start_port,end_port + 1):
       sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       sock.settimeout(1)
       result = sock.connect_ex((host,port))
       if result == 0 :
          open_port.append(port)
       sock.close()
   return open_port
#Systeme de scan en  générale et de sécurité
#MSPR fonction utiliser
#class reach_interface(Resource):
@app.route('/reach_network', methods=['GET'])
def  reach_interface():
  resultat = choose_interface()
  return jsonify(resultat)

@app.route('/informations_network', methods=['GET'])
def informations_network():
  interface = request.args.get('interface')
  resultat=get_network_info(interface)
  return jsonify({'informations':resultat})

class scan_interface_network(Resource):
    def post(self):
      data = request.get_json()
      resultat = scan_network(data['interface'])
      return jsonify({'informations':resultast})

@app.route('/get_ip_range',methods=['GET'])
def get_ip_range():
  ip=request.args.get('ip')
  netmask=request.args.get('netmask')
  resultat=get_ip_range(ip , netmask)
  return {'reponse':resultat}

@app.route('/get_headers_http',methods=['GET'])
def get_headers_http():
  url=request.args.get('url')
  reponse=http_header_analyzer(url)
  return reponse
#
class Verif_ip(Resource):
   def post(self):
      data = request.get_json()
      validity_ip=is_valid_ip(data['ip'])
      return jsonify({'message':validity_ip})

class Nmap_scan(Resource):
    def post(self):
      data = request.get_json()
      resultat_scan=nmap_port_scan(data['ip'],data['port'])
      return jsonify(resultat_scan)

class controle_password(Resource):
    def post(self):
     data = request.get_json()
     resultat=password_security_check(data['password'],)
     return jsonify({'message':resultat})

#Fin focntionne de scan
# Mise en place des modèles
class Users(db.Model, UserMixin):
    __tablename__ = 'utilisateur'
    id_utilisateur = db.Column(db.String(100), primary_key=True)
    email = db.Column(db.String(64), index=True, unique=True)
    mot_passe = db.Column(db.String(250))

class ScansInformations(db.Model):
    id_scans = db.Column(db.String(100), primary_key=True)
    path_file = db.Column(db.Text(), unique=True)

class Profil(db.Model):
    __tablename__ = 'profile'
    id_profile = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nom = db.Column(db.String(25))
    prenom = db.Column(db.String(25))
    valide = db.Column(db.String(25))
    level = db.Column(db.String(25))
    id_users = db.Column(db.String(100))

class File(db.Model):
    __tablename__ ='file_scan'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    file_path = db.Column(db.String(255))


def load_user(user_id):
    return Users.query.get(user_id)

login_manager.user_loader(load_user)
# mise eplace du systèmes accès au logs 
#@app.route('/LogServer', methods=['GET'])
@socketio.on('connect')
def fetch_logs_from_server():
    # Informations de connexion SSH pour le serveur distant
    ssh_host = '192.168.0.37'
    ssh_port = 22
    ssh_user = 'lordfire'
    ssh_password = 'azerty'
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, ssh_port, ssh_user, ssh_password)

        log_command = 'tail -n 100 /var/log/syslog'
        while True:
            stdin, stdout, stderr = ssh.exec_command(log_command)
            logs = stdout.read().decode('utf-8')

            # Envoyez les logs au client via SocketIO
            socketio.emit('logs', {'logs': logs}, namespace='/LogServer')

            # Attendre un certain temps avant de récupérer à nouveau les logs
            time.sleep(5)
    except Exception as e:
        print(f'Présence d\'une erreur {e}')

     # Informations de connexion SSH pour le serveur distant
        

@app.route('/system-resources', methods=['GET'])
def get_system_resources():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    disk_usage = psutil.disk_usage('/')

    response_data = {
        'cpu_percent': cpu_percent,
        'memory_percent': memory_info.percent,
        'disk_percent': disk_usage.percent
    }

    return jsonify(response_data)

@app.route('/running-processes', methods=['GET'])
def get_running_processes():
    processes = []

    for process in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'create_time', 'cmdline']):
        processes.append({
            'pid': process.info['pid'],
            'name': process.info['name'],
            'username': process.info['username'],
            'cpu_percent': process.info['cpu_percent'],
            'create_time': process.info['create_time'],
            'cmdline': ' '.join(process.info['cmdline']) if process.info['cmdline'] else None
        })

    return jsonify({'processes': processes})


     
@app.route('/logs', methods=['GET'])
def getlogs():
  try:
    log_command = 'cat /var/log/syslog'
    logs = subprocess.check_output(log_command, shell=True).decode('utf-8')
    logs_list = []
    for line in logs.split('\n') :
       log_info = parse_log_line(line)
       if log_info:
          logs_list.append(log_info)
    return jsonify({'logs':logs_list,'status':200})
  except Exception as e:
    return jsonify({'message':'Erreur dans la récupération des logs', 'status':500})
#
def parse_log_line(log_line):
    log_info = {}
    
    # Utilisez une expression régulière pour extraire les informations
    match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(\S+)\[(\d+)\]:\s+(.*)', log_line)
    
    if match:
        log_info['timestamp'] = match.group(1)
        log_info['level'] = match.group(2)
        log_info['process'] = match.group(3)
        log_info['pid'] = match.group(4)
        log_info['message'] = match.group(5)
        
        return log_info
    else:
        return None

#
@app.route('/all_users', methods=['GET'])
def get_all_users():
   try:
    users = Profil.query.all()
    user_list = []
    
    for user in users :
      user_data = {
        'id':user.id_profile,
        'nom':user.nom,
        'prenom':user.prenom,
        'valide':user.valide,
        'level':user.level,
        'id_users':user.id_users}
      user_list.append(user_data)
    return jsonify({'users':user_list})
   except Exception as e:
     return  jsonify({'error':str(e)})

#
@app.route('/scan-ports', methods=['GET'])
def scan_ports_route():
    target_host='localhost'
    start_port = 1
    end_port =6000
    
    open_ports = scan_ports(target_host, start_port, end_port)
    response_data = {'target_host':target_host,'open_ports':open_ports}
    return jsonify (response_data)
#
#scan_nmap
#app.route('/scan-nmap',methods['POST'])
#def scan_nmap():
#  data = request.get_json()
#  target=data.target
#  resultat = scan_ports(target)
#  return jsonify(resultat)
#
#scan owasp_zap


#
#Système d'uploads de fichier afin de les scanner
#@app.route('/upload', methods=['POST'])
#def upload_file():
  #  if 'file' not in request.files:
 #       return jsonify({'error': 'Aucun fichier trouvé dans la requête'}), 400
#
  #  uploaded_file = request.files['file']

 #   if uploaded_file.filename == '':
 #       return jsonify({'error': 'Aucun fichier sélectionné'}), 400
#
#    if uploaded_file:
#        filename = files.save(uploaded_file)
#        file_path = f'uploads/{filename}'  # Chemin du fichier par rapport à votre application
#        file_entry = File(file_path=file_path)
#        db.session.add(file_entry)
#        db.session.commit()
#        return jsonify({'message': f'Fichier {filename} téléchargé et enregistré avec succès!'}), 200
#
#    return jsonify({'error': 'Une erreur est survenue lors de l\'upload du fichier'}), 500

#
class UsersRegister(Resource):
    def post(self):
        uid = secrets.token_hex(16)
        data = request.get_json()
        password_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        verif_email = Users.query.filter_by(email=data['email']).first()
        if verif_email :
            return jsonify({'message':'Utilisateur ayant déjà un compte', 'status':400}) 
        else :
          new_user = Users(id_utilisateur=uid, email=data['email'], mot_passe=password_hash)
          db.session.add(new_user)
          db.session.commit()
          return jsonify({'message': 'Utilisateur enregistré avec succès', 'status': 200,'users_id':uid})

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = Users.query.filter_by(email=data['email']).first()

        if user and bcrypt.check_password_hash(user.mot_passe, data['password']):
            #login_user(user)  # Utilisez login_user pour gérer la connexion
            acces_token = create_access_token(identity=user.id_utilisateur)
            return jsonify({'message': 'Accès autorisé', 'status': 200, 'id_utilisateur': user.id_utilisateur, 'token':acces_token})
        else:
            return jsonify({'message': 'Identifiants incorrects', 'status': 400})

class Logout(Resource):
    @login_required
    def post(self):
        logout_user()  # Utilisez logout_user pour gérer la déconnexion
        return jsonify({'message': 'Déconnexion réussie', 'status': 200})
    

class RegisterProfil(Resource):
    def post(self):
      data = request.get_json()
      new_profil = Profil(nom=data['nom'], prenom=data['prenom'], valide=data['valide'], level=data['level'], id_users=data['users_id'])
      db.session.add(new_profil)
      db.session.commit()
      return jsonify({'message':'Enregistrement du profil','status':200})
      
#Modification
        
    
@app.route('/verif_email', methods=['GET'])
def verif_email():
    # Vous pouvez utiliser la variable 'email' directement puisque c'est déjà dans la route
    email=request.args.get('email')
    print(email)

    # Utilisez 'filter_by' sur le modèle Users pour vérifier l'e-mail
    verif_email = Users.query.filter_by(email=email).first()

    if verif_email:
        return jsonify({'status': 200, 'message': 'E-mail trouvé'})
    else:
        return jsonify({'status': 404, 'message': 'E-mail non trouvé'})      

@app.route('/get_users_by_id', methods=['GET'])
def get_users_by_id():
   id = request.args.get('id')
   verif_id = Profil.query.filter_by(id_users=id).first()
   if verif_id:
      return ({'status':200,'nom':verif_id.nom,'prenom':verif_id.prenom,'level':verif_id.level,'validity':verif_id.valide})      
   

@app.route('/modif_level', methods=['PUT'])
def modif_level():
   id = request.args.get('id')
   level = request.args.get('niveau')
   verif_id = Profil.query.filter_by(id_users=id).first()
   if verif_id:
      verif_id.level = level
      db.session.commit()
      return ({'status':200,'message':'Modification éffectuée'})      
   
@app.route('/modif_validity',methods=['PUT'])
def modif_validity():
   id= request.args.get('id')
   validity = request.args.get('validity')
   verif_id = Profil.query.filter_by(id_users=id).first()
   if verif_id:
      verif_id.valide =validity
      db.session.commit()
      return ({'status':200,'message':'Modification éffectuée'})


#Suppresssion 
        
#            
api.add_resource(UsersRegister, '/register')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(RegisterProfil,'/Register_profil')
api.add_resource(Nmap_scan,'/nmap_scan')
api.add_resource(controle_password,'/password')
api.add_resource(scan_interface_network,'/scan_interface')
# Exigez l'authentification pour accéder à certaines ressources
@login_manager.request_loader
def load_user_from_request(request):
    api_key = request.headers.get('Authorization')
    if api_key:
        user = Users.query.filter_by(api_key=api_key).first()
        if user:
            return user
    return None


@app.route('/secure-endpoint', methods=['GET'])
@jwt_required()
def secure_endpoint():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    db.create_all()
    socketio.run(app, debug=True)
