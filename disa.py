import re

# 解析 filtered.log，提取 (行号, hit次数, 地址, 机器码)
def parse_filtered_log(file_path):
    log_entries = []
    with open(file_path, "r") as file:
        for line in file:
            match = re.match(r"(\d+)\s+hit:\d+\.\s+(0x[0-9a-f]+)\s+([\da-f\s]+)", line)
            if match:
                line_number = match.group(1)
                address = match.group(2)  # 例如 0x0001156f
                machine_code = match.group(3).strip()  # 例如 "03 35 84 fc"
                reversed_machine_code = reverse_machine_code(machine_code)  # 反转字节顺序
                log_entries.append((line_number, address, reversed_machine_code, line.strip()))
    return log_entries

# 解析 assembly_debug.asm，提取 (地址, 机器码, 反汇编指令)
def parse_assembly_debug(file_path):
    asm_data = {}
    with open(file_path, "r") as file:
        for line in file:
            match = re.match(r"\s*([0-9a-f]+):\s+([0-9a-f\s]+)\s+(.+)", line)
            if match:
                address = match.group(1).lower()  # 无前缀地址，例如 "1156f"
                machine_code = match.group(2).strip().lower()  # 例如 "fc843503"
                disassembly = match.group(3).strip()
                asm_data[address] = (machine_code, disassembly)
    return asm_data

# 反转机器码字节顺序，例如 "03 35 84 fc" 变成 "fc843503"
def reverse_machine_code(machine_code):
    bytes_list = machine_code.split()  # 拆分成字节 ["03", "35", "84", "fc"]
    reversed_bytes = "".join(bytes_list[::-1])  # 反转后合并成 "fc843503"
    return reversed_bytes.lower()  # 确保一致性

# 匹配 filtered.log 和 assembly_debug.asm，并输出更新后的日志
def match_and_update_log(filtered_log_path, asm_debug_path, output_path):
    log_entries = parse_filtered_log(filtered_log_path)
    asm_data = parse_assembly_debug(asm_debug_path)

    with open(output_path, "w") as output_file:
        for line_number, address, reversed_machine_code, original_line in log_entries:
            address_hex = address[2:].lstrip("0")  # 转换 "0x0001156f" -> "1156f"
            if address_hex in asm_data and asm_data[address_hex][0] == reversed_machine_code:
                disassembly = asm_data[address_hex][1]
                output_file.write(f"{original_line} {disassembly}\n")
            else:
                output_file.write(f"{original_line} NOT_FOUND\n")  # 没找到匹配项

# 文件路径
filtered_log_path = "output.log"
assembly_debug_path = "assembly_debug.asm"
output_path = "updated_filtered.log"

# 运行匹配和更新
match_and_update_log(filtered_log_path, assembly_debug_path, output_path)

print(f"Updated log saved to {output_path}")

