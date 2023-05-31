import argparse
import requests
import time
import csv
import re

ip_regex = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
ip_regex2 = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
poc = []
apikey = ""

def query_ip(apikey, ip):
    url = "https://api.threatbook.cn/v3/ip/query"
    query = {
      "apikey": apikey,
      "resource": ip
    }
    response = requests.get(url, params=query)
    return response.json()

def NTI_scan():
    ip_list = []

    # 从文本文件中读取 IP 地址列表
    with open("uncertainty_ip.txt", "r") as file:
        ip_list = [line.strip() for line in file.readlines()]

    akui_ips = []  # 存储符合条件的 IP 地址
    uncertainty_ips = []  # 存储不符合条件的 IP 地址

    for ip in ip_list:
        result = query_ip(apikey, ip)
        judgments = result.get("data", {}).get(ip, {}).get("judgments", [])
        if any(judgment in judgments for judgment in ["C2", "Botnet", "Scanner", "Hijacked", "Malware", "Exploit", "Zombie", "Compromised", "Brute Force","Proxy","Suspicious"]):
            akui_ips.append(ip)
            print(f"{ip}是恶意ip,类型为:{judgments}")
            print("————————————————————————————————")
        else:
            uncertainty_ips.append(ip)
        
        time.sleep(0.6)

    with open("Akui_ip.txt", "a") as akui_file:
        akui_file.write("\n".join(akui_ips))

    with open("uncertainty_ip.txt", "w") as uncertain_file:
        uncertain_file.write("\n".join(uncertainty_ips))



def extract_ip_addresses(csv_file):
    ip_addresses = set()

    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            if len(row) > 7:
                data = row[7]
                matches = re.findall(ip_regex, data)
                ip_addresses.update(matches)

    return ip_addresses

def write_to_file(ip_addresses, output_file):
    with open(output_file, 'w') as file:
        file.writelines(ip + '\n' for ip in ip_addresses)

def extract_matching_rows(csv_file):
    result = set()

    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            if len(row) > 16 and any(re.search(keyword, row[16]) for keyword in poc):
                if len(row) > 7:
                    ip_match = re.search(ip_regex, row[7])
                    if ip_match:
                        result.add(ip_match.group())

    return list(result)

def compare_files(file1, file2, output_file):
    with open(file1, 'r') as f1, open(file2, 'r') as f2, open(output_file, 'w') as output:
        lines1 = set(f1.readlines())
        lines2 = set(f2.readlines())
        diff_lines2 = lines2 - lines1

        if not diff_lines2:
            output.write("没有需要您手工测试的ip.")
        else:
            output.writelines(diff_lines2)
            print("还需手工测试的ip: {}".format(output_file))

def process_files(csv_file, txt_file, output_file):
    ip_list = []
    exported_ips = set()  # 用于跟踪已导出的IP地址
    
    # 读取txt文件中的IP地址
    with open(txt_file, 'r') as txt:
        ip_list = txt.read().splitlines()
    
    # 打开csv文件进行处理
    with open(csv_file, 'r') as csv_input, open(output_file, 'w', newline='') as csv_output:
        reader = csv.reader(csv_input)
        writer = csv.writer(csv_output)
        
        for row in reader:
            if len(row) >= 8:
                ip_match = re.search(ip_regex, row[7])
                if ip_match and ip_match.group() in ip_list:
                    ip = ip_match.group()
                    if ip not in exported_ips:  # 检查IP是否已经导出过
                        # 导出第3、4、10列内容以及匹配的IP地址到新的csv文件
                        writer.writerow([row[2], ip, re.search(ip_regex2, row[9]).group(), "", row[3]+"，企图"])
                        exported_ips.add(ip)  # 将IP地址添加到已导出集合中

    
    print("处理完成！导出文件名为", output_file)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='输入一个你想分析的CSV报告.')
    parser.add_argument('-f', '--file', required=False, help='请输入一个你想分析的报告,将会导出恶意ip,全部ip,需要人工判断的ip')
    parser.add_argument('-o', '--output', required=False, help='请输入一个CSV文件,将会匹配Akui_ip.txt中的文件来导出报告')
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
    else:
        if args.file:
            csv_file = args.file

            all_ip = extract_ip_addresses(csv_file)
            all_output_file = 'All_ip.txt'
            write_to_file(all_ip, all_output_file)
            print(f'所有待调查ip保存至: {all_output_file}.\n')

            matching_rows = extract_matching_rows(csv_file)
            akui_output_file = 'Akui_ip.txt'
            write_to_file(matching_rows, akui_output_file)
            print(f'所有恶意ip保存至: {akui_output_file}.\n')

            compare_files('Akui_ip.txt', 'All_ip.txt', 'uncertainty_ip.txt')

            NTI_scan()
            print("分析完毕!请人工分析uncertainty_ip.txt中的内容")

        if args.output:
            # 指定输入文件和输出文件的路径
            csv_file = args.output
            txt_file = 'Akui_ip.txt'
            output_file = 'result.csv'

            # 调用函数处理文件
            process_files(csv_file, txt_file, output_file)
        
        
        
    
