import socket
import json

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 4433))

print("Servidor QUIC-sim (UDP) rodando na porta 4433...")

while True:
    data, addr = sock.recvfrom(2048)
    msg = data.decode()

    try:
        packet = json.loads(msg)
    except:
        packet = {"type": "unknown", "raw": msg}

    print(f"[RECV] de {addr} -> {packet}")

    # Simular resposta QUIC-like
    response = json.dumps({
        "type": "ack",
        "msg": packet.get("msg", ""),
        "info": "simulated-quic-response"
    }).encode()

    sock.sendto(response, addr)
