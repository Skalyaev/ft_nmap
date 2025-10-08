import socket

udp_ip = "0.0.0.0"
udp_port = 1024

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((udp_ip, udp_port))

print(f"UDP server listening on {udp_ip}:{udp_port}")

while True:
    try:
        data, addr = sock.recvfrom(4096)
        sock.sendto(b'\x42\x42\x42\x42', addr)

    except Exception as e:
        print(f"Error: {e}")

