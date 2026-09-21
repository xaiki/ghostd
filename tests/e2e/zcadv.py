#!/usr/bin/python3
"""A container's own DNS-SD advertisement, plus the service it advertises: the
lab's stand-in for an application that speaks mDNS itself on its container
network. Run inside the container namespace.

  zcadv.py <name> <host> <address> <port> [<seconds>]
"""
import os
import signal
import socket
import sys
import threading
import time

from zeroconf import ServiceInfo, Zeroconf

name, host, address, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
lifetime = float(sys.argv[5]) if len(sys.argv) > 5 else 3600

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((address, port))
srv.listen(8)


def serve():
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        conn.sendall(("HELLO-FROM-CONTAINER %s\n" % name).encode())
        conn.close()


threading.Thread(target=serve, daemon=True).start()
zc = Zeroconf(interfaces=[address])
info = ServiceInfo("_ipp._tcp.local.", "%s._ipp._tcp.local." % name, addresses=[socket.inet_aton(address)], port=port,
                   properties={"rp": "ipp/print"}, server="%s.local." % host)
zc.register_service(info)
print("registered", flush=True)


def stop(*_):
    zc.unregister_service(info)  # goodbye
    zc.close()
    os._exit(0)


signal.signal(signal.SIGTERM, stop)
time.sleep(lifetime)
stop()
