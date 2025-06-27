import nmap
import json
import csv

def scan_reseau(cible):
    scanner = nmap.PortScanner()
    scanner.scan(cible, arguments='-sV')
    return scanner

def exporter_resultats_csv(scanner, nom_fichier='resultats_scan.csv'):
    with open(nom_fichier, 'w', newline='') as fichier_csv:
        writer = csv.writer(fichier_csv)
        writer.writerow(['IP', 'Port', 'Service', 'État'])

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in scanner[host][proto]:
                    data = scanner[host][proto][port]
                    writer.writerow([
                        host,
                        port,
                        data.get('name'),
                        data.get('state')
                    ])

def detecter_vulnerabilites(scanner, fichier_ports='ports_vuln.json'):
    with open(fichier_ports, 'r') as f:
        ports_vuln = json.load(f)

    alertes = []

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                if str(port) in ports_vuln:
                    alertes.append({
                        'IP': host,
                        'Port': port,
                        'Service': scanner[host][proto][port]['name'],
                        'Risque': ports_vuln[str(port)]
                    })

    return alertes
