from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import paramiko
from getpass import getpass

# Génération des clés RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Sauvegarde de la clé privée
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

with open('private_key.pem', 'wb') as f:
    f.write(private_pem)
print("Clé privée sauvegardée dans private_key.pem")

# Génération de la clé publique
public_key = private_key.public_key()

ssh_public = public_key.public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH
)
ssh_public_str = ssh_public.decode().strip()

with open('public_key.pub', 'wb') as f:
    f.write(ssh_public)
print("Clé publique sauvegardée dans public_key.pub")

# Configuration de la connexion SSH
host = input("Adresse du serveur: ")
username = input("Nom d'utilisateur SSH: ")
password = getpass("Mot de passe SSH: ")

# Connexion au serveur
ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    ssh_client.connect(
        hostname=host,
        username=username,
        password=password
    )
    sftp = ssh_client.open_sftp()
    
    # Vérification/Création du dossier .ssh
    try:
        sftp.stat('.ssh')
    except FileNotFoundError:
        sftp.mkdir('.ssh', 0o700)
        print("Création du dossier .ssh")

    # Ajout de la clé publique
    auth_keys_path = '.ssh/authorized_keys'
    
    try:
        with sftp.file(auth_keys_path, 'r') as f:
            existing_keys = f.read().decode()
    except FileNotFoundError:
        existing_keys = ''

    if ssh_public_str not in existing_keys:
        new_content = f"{existing_keys}\n{ssh_public_str}" if existing_keys else ssh_public_str
        with sftp.file(auth_keys_path, 'w') as f:
            f.write(new_content)
        sftp.chmod(auth_keys_path, 0o600)
        print("Clé publique ajoutée avec succès au serveur")
    else:
        print("La clé publique est déjà présente sur le serveur")

    sftp.close()

except Exception as e:
    print(f"Erreur: {str(e)}")
finally:
    ssh_client.close()