import csv
import re
import argparse

ip_regex = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

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
                        writer.writerow([row[2], ip, row[9], "", row[3]+"，试图"])
                        exported_ips.add(ip)  # 将IP地址添加到已导出集合中

    
    print("处理完成！导出文件名为", output_file)




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='输入一个你想分析的CSV报告.')
    parser.add_argument('-f', '--file', required=True, help='Input CSV file')
    args = parser.parse_args()

    # 指定输入文件和输出文件的路径
    csv_file = args.file
    txt_file = 'Akui_ip.txt'
    output_file = 'result.csv'

    # 调用函数处理文件
    process_files(csv_file, txt_file, output_file)