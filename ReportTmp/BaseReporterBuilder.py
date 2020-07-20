# coding = "utf-8"


class BaseReporter(object):
    def __init__(self):
        self.name = "simple reporter"
        self.path = "report.html"

    def build(self, data):
        html_content = """ <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>扫描报告</title>
            <link href="http://libs.baidu.com/bootstrap/3.0.3/css/bootstrap.min.css" rel="stylesheet">
            <h2 style="font-family: Microsoft YaHei">信息搜集</h2>
            <style type="text/css" media="screen">
        body  { font-family: Microsoft YaHei,Tahoma,arial,helvetica,sans-serif;padding: 20px;}
        td {text-align:center}
        th {text-align:center}
        </style>
        </head>
        <body>
            <p>子域名信息</p>
            <table id='result_table' class="table table-condensed table-bordered table-hover" >
                <colgroup>
                    <col align='left' />
                    <col align='right' />
                    <col align='right' />
                    <col align='right' />
                </colgroup>
                <tr id='header_row' class="text-center warning " style="font-weight: bold;font-size: 14px;">
                    <th width="20%">域名</th>
                    <th width="20%">来源</th>
                    <th width="20%">IP地址</th>
                    <th width="20%">端口号</th>
                    <th width="20%">协议</th>
                </tr> """
        sublist_data_dic = {}
        for data_line in data:
            for scanner_name in data_line:
                for sub_domain_data in data_line[scanner_name].keys():
                    if sub_domain_data in sublist_data_dic:
                        sublist_data_dic[sub_domain_data].extend(data_line[scanner_name][sub_domain_data])
                    else:
                        sublist_data_dic[sub_domain_data] = [data_line[scanner_name][sub_domain_data]]
        for sub_domain in sublist_data_dic.keys():
            for domain_data in sublist_data_dic[sub_domain]:
                if type(domain_data) == list:
                    for td_item in domain_data:
                        html_content += f"""<tr class='failClass info'>
                                <td>{sub_domain}</td>
                                <td>{td_item['source']}</td>
                                <td>{td_item['ip_address']}</td>
                                <td>{td_item['port']}</td>
                                <td>{td_item['protocol']}</td></tr>"""
                elif type(domain_data) == dict:
                    html_content += f"""<tr class='failClass info'>
                                                    <td>{sub_domain}</td>
                                                    <td>{domain_data['source']}</td>
                                                    <td>{domain_data['ip_address']}</td>
                                                    <td>{domain_data['port']}</td>
                                                    <td>{domain_data['protocol']}</td></tr>"""
        html_content += """</table></body></html>"""
        with open(self.path, 'w', encoding='utf-8') as report_file:
            report_file.write(html_content)
