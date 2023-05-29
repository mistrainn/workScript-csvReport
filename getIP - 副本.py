import argparse
import csv
import re

ip_regex = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
poc = ["123"]

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



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='输入一个你想分析的CSV报告.')
    parser.add_argument('-f', '--file', required=True, help='Input CSV file')
    args = parser.parse_args()

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
