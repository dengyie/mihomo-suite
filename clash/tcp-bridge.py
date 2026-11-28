#!/usr/bin/env python3
"""TCP 透传桥 (UDP 不可达时给 TCP 客户端一个 TCP 入口, 转发到本机 UDP 服务端口)."""
import argparse
import socket
import threading
import select
import sys

def forward(src, dst):
    try:
        while True:
            r, _, _ = select.select([src, dst], [], [])
            if src in r:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
            if dst in r:
                data = dst.recv(65536)
                if not data:
                    break
                src.sendall(data)
    except Exception:
        pass
    finally:
        try:
            src.close()
        except Exception:
            pass
        try:
            dst.close()
        except Exception:
            pass

def handle_client(client_sock, target_host, target_port):
    try:
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.settimeout(10)
        remote_sock.connect((target_host, target_port))
        remote_sock.settimeout(None)
        client_sock.settimeout(None)
        forward(client_sock, remote_sock)
    except Exception:
        try:
            client_sock.close()
        except Exception:
            pass

def run_bridge(listen_host, listen_port, target_host, target_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(128)
    print("Bridge listening on " + listen_host + ":" + str(listen_port) + " -> " + target_host + ":" + str(target_port))
    sys.stdout.flush()
    while True:
        client, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client, target_host, target_port), daemon=True)
        t.start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--listen-host', default='0.0.0.0')
    parser.add_argument('--listen-port', type=int, required=True)
    parser.add_argument('--target-host', default='127.0.0.1')
    parser.add_argument('--target-port', type=int, required=True)
    args = parser.parse_args()
    run_bridge(args.listen_host, args.listen_port, args.target_host, args.target_port)
