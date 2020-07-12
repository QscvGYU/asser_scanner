# coding = 'utf-8'
import socket


class BaseIPScanner(object):
    def __init__(self):
        self.scanner_name = "base"

    def get_ip(self, domain: str) -> list:
        return socket.getaddrinfo(domain)

    def get_ips(self, domains: list) -> dict:
        rst = {}
        for domain in domains:
            rst[domain] = self.get_ip(domain)
        return rst



