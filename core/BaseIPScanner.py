# coding = 'utf-8'
import socket


class BaseIPScanner(object):
    def __init__(self):
        self.scanner_name = "base"

    def get_ip(self, domain: str) -> list:
        try:
            return socket.getaddrinfo(domain, "https")
        except Exception:
            return None

    def get_ips(self, domains: list) -> dict:
        rst = {}
        for domain in domains:
            ip_address = self.get_ip(domain)
            if ip_address is not None:
                rst[domain] = self.get_ip(domain)
        return rst

