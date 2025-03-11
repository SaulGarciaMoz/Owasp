#!/usr/bin/python3

from pwn import log
from urllib.parse import urlparse
import requests, sys, nmap, signal, os, socket

def def_handler(sig, frame):
    print("\n[!] Detección de interrupción del programa...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Validar las entradas
#if os.geteuid() != 0:
#   print("\n[!] Este script requiere permisos de administrador!\n ")
#   sys.exit(1)

if len(sys.argv) != 2:
    print("\nNúmero incorrecto de entradas...")
    print("\n[!] Uso: python3 script.py <URL>\n")
    sys.exit(1)

# Función escaneo de puertos
def Nmap_Ports(target):
    """
    Escanear puertos abiertos y obtener versiones utilizando Nmap.
    """
    # PARCEAR URL
    parsed_url = urlparse(target)
    host = parsed_url.netloc if parsed_url.netloc else target
    try:
        ip = socket.gethostbyname(host)
        print(f"\nResolviendo IP para {host}: {ip}")
    except socket.gaierror as e:
        log.error(f"Error al obtener la IP de {host}: {e}")
        sys.exit(1)

    # Opciones de Nmap 
    options = "-p- --open -sS -sCV -n -Pn --min-rate 5000"

    try:
        # Instancia del escaneador Nmap
        scanner = nmap.PortScanner()
        # Barra de Progreso
        Prog_nmap = log.progress("Escaneando puertos abiertos y obteniendo versiones... ")
        scanner.scan(ip, arguments=options)

        # Procesar los resultados
        for host in scanner.all_hosts():
            print(f"\nHost: {host} {ip}")
            print(f"Estado: {scanner[host].state()}")

            if 'tcp' in scanner[host]:
                Prog_nmap.success("Escaneo completado con éxito")
                print("Puertos abiertos y servicios detectados:")
                for port in scanner[host]['tcp']:
                    port_info = scanner[host]['tcp'][port]
                    print(f"\nPuerto: {port}")
                    print(f"  Estado: {port_info['state']}")
                    print(f"  Servicio: {port_info.get('name', 'Desconocido')}")
                    print(f"  Versión: {port_info.get('product', 'No detectada')} {port_info.get('version', '')}")
                    print(f"  Información adicional: {port_info.get('extrainfo', 'N/A')}")
            else:
                print("No se encontraron puertos abiertos.")
    except nmap.PortScannerError as e:
        Prog_nmap.failure(f"Error durante el escaneo: {e}")

# Función principal
if __name__ == '__main__':
    # Hacer una validación de que funcione la URL antes de llamar la función
    try:
        response = requests.get(sys.argv[1])
        if response.status_code == 200:
            Nmap_Ports(sys.argv[1])
        else:
            print(f"\n[!] Error al acceder a la URL: {response.status_code}")
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"\n[!] Error al realizar la solicitud HTTP: {e}")
        sys.exit(1)
