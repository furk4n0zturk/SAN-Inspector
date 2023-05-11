import argparse
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class SSLChecker:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def check_san(self):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers('DEFAULT@SECLEVEL=1')
            with socket.create_connection((self.host, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())

            subject = cert.subject
            domain = None
            for attribute in subject:
                if attribute.oid._name == "commonName":
                    domain = attribute.value
                    break

            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_domains = san.value.get_values_for_type(x509.DNSName)
            print("Host: ", self.host)
            print(f"Issued to: {domain}")
            print("SAN Value:")
            for d in san_domains:
                print(f'- {d}')

            if self.host in san_domains or self.host == domain:
                print("[+] It matches\n")
            else:
                print("[!] Not matches\n")

        except Exception as e:
            print(f"Hata: {e}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check SSL SAN values for given hosts.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', metavar='host:port', help='Single host with port, e.g., example.com:443')
    group.add_argument('-uL', '--url_list', metavar='hostlist.txt', help='File containing list of hosts with ports')
    args = parser.parse_args()

    if args.url:
        host, port = args.url.split(':')
        port = int(port)
        checker = SSLChecker(host, port)
        checker.check_san()
    elif args.url_list:
        with open(args.url_list, 'r') as f:
            for line in f.readlines():
                host, port = line.strip().split(':')
                port = int(port)
                checker = SSLChecker(host, port)
                checker.check_san()
