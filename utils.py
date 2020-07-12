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
