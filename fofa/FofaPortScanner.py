# coding = 'utf-8'
import json

from core.BasePortScanner import BasePortScanner
from fofa.FofaClent import FofaClient


class FofaPortScanner(BasePortScanner):
    def __init__(self):
        self.name = "fofa"
        self.fofa_client = FofaClient()

    def scan(self,  ip_address: str) -> list:
        """【可选参数】字段列表，默认为host，用逗号分隔多个参数，如(fields=ip,title)，
        可选的列表有：
        host title ip domain port country province city country_name header server protocol
         banner cert isp as_number as_organization latitude longitude lastupdatetime
        """
        # field_list = ["host","title","domain","ip","country","province","city","country_name",
        # "header","server","protocol","banner","cert","isp"]
        rst = []
        query_str = f'ip="{ip_address}"'
        field_list = ["host", "protocol", "cert", "header"]
        for page in [1]:
            user_info = self.fofa_client.get_user_info()
            # print(f"fcoin : {user_info['fcoin']}")
            rst.extend(
                self.deal_rst(field_list, self.fofa_client.get_data(query_str, page=page,
                                          fields=str.join(",", field_list))))

    def get_user_info(self):
        return self.fofa_client.get_user_info()

    def deal_rst(self, field_list, scan_rst) -> list:
        rst = []
        if "results" not in scan_rst:
            return rst
        if len("scan_rst") == 0:
            return rst
        for data_line in scan_rst["results"]:
            rst_item = {}
            if len(str(data_line[0]).split(":")) > 1:
                rst_item["port"] = str(data_line[0]).split(":")[1]
            else:
                rst_item["port"] = "80"
            rst_item["protocol"] = data_line[1]
            rst_item["ssl"] = data_line[2]
            rst_item["header"] = data_line[3]
            rst_item["cpe"]: ""
            rst.append(rst_item)
        return rst



