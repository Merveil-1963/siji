from OpenSSL import crypto
import os

def create_self_signed_cert():
    # Générer une paire de clés
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # Créer un certificat
    cert = crypto.X509()
    cert.get_subject().C = "FR"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Organization"
    cert.get_subject().OU = "Organizational Unit"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # Valide pour 1 an
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    # Sauvegarder le certificat
    with open("certs/cert.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    # Sauvegarder la clé privée
    with open("certs/cert.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

    print("Certificat et clé générés avec succès dans le dossier 'certs'")

if __name__ == '__main__':
    create_self_signed_cert() 