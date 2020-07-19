# coding = 'utf-8'


class BasePortScanner(object):
    """
    这是一个通过IP地址扫描该IP开放端口以及详细信息的基类
    """
    def __init__(self):
        pass

    def scan(self, ip_address: str)-> list:
        pass

