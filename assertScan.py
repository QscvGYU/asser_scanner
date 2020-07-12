# coding = 'utf-8'

from core.BaseIPScanner import BaseIPScanner
from fofa.FofaPortScanner import FofaPortScanner
from Sublist3r.sublist3r import interactive as sublist_interactive
from shodan_ext.ShodanPortScanner import ShodanPortScanner


def main():
    sub_domain_list = sublist_interactive()
    ip_scanner = BaseIPScanner()
    sub_domain_ip_map = ip_scanner.get_ips(sub_domain_list)
    scanner_list =  [
        FofaPortScanner, ShodanPortScanner
    ]
    scanners = [scanner() for scanner in scanner_list]
    for sub_domain in sub_domain_ip_map.keys():
        ip_address_list = sub_domain_ip_map[sub_domain]
        for ip_address in ip_address_list:
            for scanner in scanners:
                scanner.scan(ip_address)


if __name__ == "__main__":
    main()