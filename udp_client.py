import socket
import json
import time

server_ip = "10.0.0.1"  # ajustar para IP real do servidor
server_port = 4433

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

handshake = json.dumps({
    "type": "handshake",
    "msg": "hello-quic-sim"
}).encode()

sock.sendto(handshake, (server_ip, server_port))
print("[SEND] handshake enviado.")

data, _ = sock.recvfrom(2048)
print("[RECV] resposta:", data.decode())

# Enviar pacote de “dados QUIC-like”
time.sleep(1)
payload = json.dumps({
    "type": "data",
    "msg": "conteudo simulacao"
}).encode()

sock.sendto(payload, (server_ip, server_port))
print("[SEND] payload enviado.")

resp, _ = sock.recvfrom(2048)
print("[RECV]", resp.decode())