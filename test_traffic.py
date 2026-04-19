# test_traffic.py - Run this in a separate terminal while sniffer is running
import socket
import time

# Test 1: Normal HTTP request
print("Sending test HTTP packet...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(("example.com", 80))
    s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    print("HTTP packet sent")
except:
    print("HTTP test failed")
s.close()

# Test 2: UDP packet
print("Sending test UDP packet...")
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.sendto(b"Test UDP payload", ("8.8.8.8", 53))
print("UDP packet sent")

# Test 3: Multiple packets to trigger DoS alert
print("Sending multiple packets (testing DoS detection)...")
for i in range(35):  # 35 packets - should trigger DoS alert if threshold is 30
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("google.com", 80))
        s.send(b"GET / HTTP/1.1\r\n\r\n")
    except:
        pass
    s.close()
    time.sleep(0.1)
    print(f"Packet {i+1}/35 sent")

print("Test complete!")