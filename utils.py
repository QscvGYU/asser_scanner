# coding = 'utf-8'


def intToIp(ip_int):
    ip_bin = bin(ip_int)[2:]
    ip_bin = ip_bin.zfill(32)

    bin_list = []
    ip_str = []

    for i in range(0, 32, 8):
        bin_list.append(ip_bin[i:i + 8])

    for temp in bin_list:
        ip_str.append(str(int(temp, 2)))

    ret = ".".join(ip_str)
    return ret


def get_dic_data(dic_data: dict, key: str, default_value):
    if key in dic_data:
        return dic_data[key]
    else:
        return default_value


def can_convert_int(int_value :str):
    try:
        int(int_value)
        return True
    except Exception:
        return False




