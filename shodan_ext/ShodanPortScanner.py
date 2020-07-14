# coding = 'utf-8'
import json

from core.BasePortScanner import BasePortScanner
from shodan_ext.ShodanClientExt import ShodanClientExt
from utils import get_dic_data


class ShodanPortScanner(BasePortScanner):
    def __init__(self):
        self.name = "shodan"
        self.shodan_client = ShodanClientExt()

    def scan(self, ip_address: str):
        self.deal_rst(self.shodan_client.search_host(ip_address))

    def deal_rst(self, scan_rst):
        rst = []
        if "data" not in scan_rst:
            return rst
        if len(scan_rst["data"]) == 0:
            return rst
        for data_line in scan_rst["data"]:
            rst_item = {
                "port": get_dic_data(scan_rst["data"], ["port"], ""),
                "protocol": get_dic_data(scan_rst["data"], "transport", ""),
                "ssl": json.dumps(get_dic_data(scan_rst["data"], "ssl", "{}")),
                "header": get_dic_data(scan_rst["data"], "data", ""),
                "cpe": json.dumps(get_dic_data(scan_rst["data"], "cpe", "{}"))
            }
            rst.append(rst_item)
        return rst