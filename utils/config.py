import socket
import subprocess
import sys
import re

def get_interface_info():
    interfaces = []
    
    if sys.platform == "win32":
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
            lines = result.stdout.split('\n')
            
            current_iface = None
            for i, line in enumerate(lines):
                adapter_match = re.match(r'(\S.+? adapter) (.+?):', line)
                if adapter_match:
                    current_iface = adapter_match.group(2).strip()
                
                ip_match = re.search(r'IPv4 Address[.\s]+:\s(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match and current_iface and ip_match.group(1) != "0.0.0.0":
                    interfaces.append({
                        "name": current_iface,
                        "ip": ip_match.group(1)
                    })
                    current_iface = None
        except:
            pass
    
    else:
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                ip = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', '')
                if ip and ip != "127.0.0.1":
                    interfaces.append({"name": iface, "ip": ip})
        except ImportError:
            try:
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                
                current_iface = None
                for line in lines:
                    iface_match = re.match(r'\d+:\s(\w+):', line)
                    if iface_match:
                        current_iface = iface_match.group(1)
                    
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match and current_iface and ip_match.group(1) != "127.0.0.1":
                        interfaces.append({"name": current_iface, "ip": ip_match.group(1)})
                        current_iface = None
            except:
                pass
    
    if not interfaces:
        interfaces = [{"name": "Default Interface", "ip": "Auto-detected by Scapy"}]
    
    return interfaces