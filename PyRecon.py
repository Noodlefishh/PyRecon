# PyRecon - 2025
# A lightweight and simple python tool to help you in external attack surface and reconnaissance
# Created by Noodlefish
# Free to use -> No BS -> you do you.
# subdomain list provided by rbsec & rajesh6927 on GitHub

import requests
import ssl
import socket
import dns
import dns.resolver
from datetime import datetime, timezone
import whois
import certifi
from concurrent.futures import ThreadPoolExecutor

#########################
#       MAIN MENU       #
#########################
print("1 : Scan a domain")
print("2 : Check certificate informations")
print("3 : Check DNS informations")
print("4 : Check open port")
main_menu_choice = int(input("Please choose what you want to do : "))


#########################
#   DOMAIN SCANNING     #
#########################
if main_menu_choice == 1 :
   print("You are about to scan a domain, please enter the targeted domain: ")

   def domain_scanner(domain_name, sub_domnames):
       print('-----------Scanner Started-----------')
       print('-------Scanning for subdomain--------')
       print('-------Grab a coffee and enjoy-------')

       for subdomain in sub_domnames:

           url = f"https://{subdomain}.{domain_name}"

           try:
               requests.get(url)
               print(f'[+] {url}')
           except requests.ConnectionError:
               pass
       print('\n')
       print('----Scanning Finished and stopped----')

   if __name__ == '__main__':

       dom_name = input("Enter the Domain Name : ")
       print('\n')

       with open('subdomain_list2025.txt', 'r') as file:
           name = file.read()
           sub_dom = name.splitlines()

       domain_scanner(dom_name, sub_dom)

#########################
#   CERTIFICATE MODULE  #
#########################
elif main_menu_choice == 2 :

    def get_ssl_certificate(hostname, port=443):
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        except Exception as e:
            print(f"An error occurred while retrieving the SSL certificate: {e}")
            return None


    def print_cert_info(cert):
        if not cert:
            print("No certificate information available.")
            return

        def format_date(timestamp):
            return datetime.strptime(timestamp, "%b %d %H:%M:%S %Y %Z")

        print("Issuer:")
        for item in cert.get('issuer', []):
            for key, value in item:
                print(f"  {key}: {value}")

        print("\nSubject:")
        for item in cert.get('subject', []):
            for key, value in item:
                print(f"  {key}: {value}")

        print("\nValidity Period:")
        try:
            print(f"  Not Before: {format_date(cert['notBefore'])}")
            print(f"  Not After: {format_date(cert['notAfter'])}")
        except Exception as e:
            print(f"Error formatting date: {e}")

        print("\nSubject Alternative Names:")
        for san in cert.get('subjectAltName', []):
            print(f"  {san[0]}: {san[1]}")

        print("\nSerial Number:")
        print(f"  {cert['serialNumber']}")

        print("\nVersion:")
        print(f"  {cert['version']}")

    if __name__ == "__main__":
        hostname = input("Enter the domain name: ")
        cert = get_ssl_certificate(hostname)
        print_cert_info(cert)

#########################
#      DNS MODULE       #
#########################
if main_menu_choice == 3 :

    def query_domain(domain):
        try:
            domain_info = whois.whois(domain)
            print("Domain Name:", domain_info.domain_name)
            print("Registrar:", domain_info.registrar)
            print("Whois Server:", domain_info.whois_server)
            print("Referral URL:", domain_info.referral_url)
            print("Updated Date:", domain_info.updated_date)
            print("Creation Date:", domain_info.creation_date)
            print("Expiration Date:", domain_info.expiration_date)
            print("Name Servers:", domain_info.name_servers)
            print("Status:", domain_info.status)
            print("Emails:", domain_info.emails)
            print("DNSSEC:", domain_info.dnssec)
            print("Name:", domain_info.name)
            print("Org:", domain_info.org)
            print("Address:", domain_info.address)
            print("City:", domain_info.city)
            print("State:", domain_info.state)
            print("Zipcode:", domain_info.zipcode)
            print("Country:", domain_info.country)

            dns_records(domain)

        except Exception as e:
            print(f"An error occurred: {e}")

    def dns_records(domain):
        try:
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for data in answers:
                        print(f"{record_type} Record: {data}")
                except dns.resolver.NoAnswer:
                    print(f"No {record_type} record found for {domain}")
                except dns.resolver.NXDOMAIN:
                    print(f"The domain {domain} does not exist.")
                except dns.resolver.Timeout:
                    print(f"Query for {record_type} record timed out.")
                except Exception as e:
                    print(f"An error occurred while querying {record_type} record: {e}")
        except dns.resolver.NoNameservers:
            print("No nameservers found for the domain.")
        except Exception as e:
            print(f"An error occurred while querying DNS records: {e}")

    if __name__ == "__main__":
        domain = input("Enter the domain name: ")
        query_domain(domain)

#########################
#   POOR'S MAN NMAP     #
#########################
if main_menu_choice == 4:

    # List of common ports
    COMMON_PORTS = {
        20: "FTP",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "RPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1723: "PPTP",
        3306: "MySQL",
        3389: "RDP",
        5900: "VNC",
        8080: "HTTP-Proxy",
    }


    def scan_port(domain, port):
        try:
            with socket.create_connection((domain, port), timeout=1) as s:
                return port, "open"
        except socket.timeout:
            return port, "filtered"
        except ConnectionRefusedError:
            return port, "closed"
        except OSError as e:
            return port, f"error ({e})"


    def scan_ports(domain):
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_port, domain, port) for port in COMMON_PORTS]
            for future in futures:
                port, status = future.result()
                print(f"Port {port} ({COMMON_PORTS[port]}): {status}")


    if __name__ == "__main__":
        domain = input("Enter the domain name: ")
        scan_ports(domain)

#Wrong main menu choice
else:
    print("error")
