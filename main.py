import nmap

# Definir el rango de IP a escanear
target_ip_range = "192.168.0.1-10"
target_port_range = "-p 1-65535 -T4"

# Crear un objeto de escaneo Nmap
nm = nmap.PortScanner()

# Realizar un escaneo de puertos en el rango de IP especificado
nm.scan(hosts=target_ip_range, arguments=target_port_range)

# Iterar a través de las direcciones IP escaneadas y sus puertos
for host in nm.all_hosts():
    print(f"Host: {host}")
    for proto, ports in nm[host].items():
        if proto == 'tcp':
            for port, port_data in ports.items():
                port_number = port
                port_state = port_data['state']
                service_name = port_data['name'] or 'N/A'
                print(
                    f"  Port: {port_number} - State: {port_state} - Service: {service_name}")

# Realizar un escaneo de detección de versiones en los puertos abiertos
for host in nm.all_hosts():
    print(f"Host: {host}")
    for port, port_data in nm[host]['tcp'].items():
        if port_data['state'] == 'open':
            port_number = port
            print(f"Scanning port {port_number} for vulnerabilities...")
            nmap_args = f"-sV --script vulners -p {port_number}"
            vuln_scan = nm.scan(hosts=host, arguments=nmap_args)
            vulnerabilities = vuln_scan.get('scan')[host].get('tcp')[
                port_number].get('script', '')
            if vulnerabilities:
                print(f"  Vulnerabilities on port {port_number}:")
                for vuln, vuln_details in vulnerabilities.items():
                    print(f"    {vuln}: {vuln_details}")
