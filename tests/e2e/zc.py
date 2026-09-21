#!/usr/bin/python3
"""A third-party mDNS client (python-zeroconf) for the e2e lab. Run inside the
LAN client namespace, so ghostd is answering a host that is not itself.

  zc.py info   <type> <instance-fqdn>   -> port=... addrs=a,b server=... txt=k=v;...   (or "none")
  zc.py browse <type>                   -> one instance name per line
"""
import sys
import time

from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

zc = Zeroconf(interfaces=["10.77.0.60"])
try:
    mode = sys.argv[1]
    if mode == "info":
        info = zc.get_service_info(sys.argv[2], sys.argv[3], timeout=4000)
        if info is None:
            print("none")
        else:
            txt = ";".join("%s=%s" % (k.decode(), (v or b"").decode()) for k, v in info.properties.items())
            print("port=%d addrs=%s server=%s txt=%s" % (info.port, ",".join(sorted(info.parsed_addresses())), info.server, txt))
    elif mode == "browse":
        found = set()

        class L(ServiceListener):
            def add_service(self, z, t, n):
                found.add(n)

            def update_service(self, z, t, n):
                pass

            def remove_service(self, z, t, n):
                found.discard(n)

        ServiceBrowser(zc, sys.argv[2], L())
        time.sleep(3)
        for n in sorted(found):
            print(n)
finally:
    zc.close()
