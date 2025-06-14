import re

def reverse_machine_code(machine_code):
    bytes_list = machine_code.split()  # 拆分成字节列表
    return "".join(bytes_list[::-1]).lower()  # 反转后合并成字符串

def parse_assembly_debug(file_path):
    asm_data = {}
    with open(file_path, "r") as file:
        for line in file:
            match = re.match(r"\s*([0-9a-f]+):\s+([0-9a-f\s]+)\s+(.+)", line)
            if match:
                address = match.group(1).lower()  # 例如 "1156f"
                machine_code = match.group(2).strip().lower()  # "fc843503"
                disassembly = match.group(3).strip()
                asm_data[address] = (machine_code, disassembly)
    return asm_data

def process_logs(filtered_log_path, asm_debug_path, output_path):
    asm_data = parse_assembly_debug(asm_debug_path)  # 先解析 assembly_debug.asm
    
    with open(filtered_log_path, "r") as log_file, open(output_path, "w") as output_file:
        for line in log_file:
            match = re.match(r"(\d+)\s+hit:\d+\.\s+(0x[0-9a-f]+)\s+([\da-f\s]+)", line)
            if match:
                line_number = match.group(1)
                address = match.group(2)  # 例如 0x0001156f
                machine_code = match.group(3).strip()  # "03 35 84 fc"
                reversed_machine_code = reverse_machine_code(machine_code)
                
                address_hex = address[2:].lstrip("0")  # "0x0001156f" -> "1156f"
                if address_hex in asm_data and asm_data[address_hex][0] == reversed_machine_code:
                    disassembly = asm_data[address_hex][1]
                    output_file.write(f"{line.strip()} {disassembly}\n")
                else:
                    output_file.write(f"{line.strip()} NOT_FOUND\n")
    
    print(f"Updated log saved to {output_path}")

# 文件路径
filtered_log_path = "output.log"
assembly_debug_path = "assembly_debug.asm"
output_path = "updated_filtered.log"

# 运行
process_logs(filtered_log_path, assembly_debug_path, output_path)
