# coding = 'utf-8
import json
import shodan


class ShodanClientExt(object):
    def __init__(self):
        self.config_path = "shodan_ext"
        self.api_key = ""
        self.email = ""
        self.init_config()
        self.api_client = shodan.Shodan(self.api_key)

    def init_config(self):
        config_file_path = fr"./{self.config_path}/config.json"
        with open(config_file_path, 'r', encoding='utf-8') as config_file:
            config_json = config_file.read()
            config_obj = json.loads(config_json)
            self.api_key = config_obj["api_key"]
            self.email = config_obj["email"]

    def search_host(self, host: str):
        try:
            return self.api_client.host(host)
        except shodan.exception.APIError:
            return "No information available for that IP"

    def search(self, query: str):
        return self.api_client.search(query)

