# coding = 'utf-8'
import json

import nmap
from core.BasePortScanner import BasePortScanner
from utils import get_dic_data


class NMapPortScannser(BasePortScanner):
    def __init__(self):
        self.name = "nmap"
        self.client = nm = nmap.PortScanner()
        self.config_path = "/nmap_ext"
        self.config_path = "./"
        self.arg = ""
        self.init_config()


    def scan(self, ip_address: str) -> list:
        self.client.scan(ip_address, arguments=f'{ip_address} {self.arg}')
        if ip_address in self.client._scan_result['scan']:
            return self.deal_rst(self.client._scan_result['scan'][ip_address],ip_address)
        else:
            return None

    def deal_rst(self, scan_rst, ip_address):
        rst = []
        if "tcp" in scan_rst:
            for tcp_port in scan_rst['tcp'].keys():
                rst_item = {
                    "port": tcp_port,
                    "protocol": get_dic_data(scan_rst["tcp"][tcp_port], "name", ''),
                    "ssl": "",
                    "header": get_dic_data(scan_rst["tcp"][tcp_port], "version", ''),
                    "cpe": "",
                    "ip_address": ip_address,
                    "source": self.name
                }
                rst.append(rst_item)
        return rst

    def init_config(self):
        config_file_path = fr"./{self.config_path}/config.json"
        with open(config_file_path, 'r', encoding='utf-8') as config_file:
            config_json = config_file.read()
            config_obj = json.loads(config_json)
            self.arg = config_obj["namp_arg"]


