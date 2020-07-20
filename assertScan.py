# coding = 'utf-8'
import json

from ReportTmp.BaseReporterBuilder import BaseReporter
from core.BaseIPScanner import BaseIPScanner
from fofa.FofaPortScanner import FofaPortScanner
from Sublist3r.sublist3r import interactive as sublist_interactive
from nmap_ext.NMapPortScaner import NMapPortScannser
from shodan_ext.ShodanPortScanner import ShodanPortScanner


def main():
    sub_domain_list = sublist_interactive()
    ip_scanner = BaseIPScanner()
    sub_domain_ip_map = ip_scanner.get_ips(sub_domain_list)
    scanner_list = [
        FofaPortScanner, ShodanPortScanner, NMapPortScannser
    ]
    rst = []
    scanners = [scanner() for scanner in scanner_list]
    for scanner in scanners:
        for sub_domain in sub_domain_ip_map.keys():
            ip_scan_rst = {}
            ip_address_list = sub_domain_ip_map[sub_domain]
            for ip_address in ip_address_list:
                if ip_address is None:
                    continue
                scan_rst_item = scanner.scan(ip_address[4][0])
                if scan_rst_item:
                    if sub_domain in ip_scan_rst:
                        ip_scan_rst[sub_domain].extend(scan_rst_item)
                    else:
                        ip_scan_rst[sub_domain] = scan_rst_item
            rst.append({scanner.name: ip_scan_rst})
    BaseReporter().build(rst)


if __name__ == "__main__":
    main()