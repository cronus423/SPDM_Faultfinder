import re

# 输入和输出文件路径
input_file = "updated_filtered.log"
output_file = "xor_lines_without_hash.log"

# 目标地址范围（跳过此范围内的地址）
skip_start = 0x93F98
skip_end = 0x94970

def find_xor_lines(input_file, output_file):
    xor_lines = []  # 存储匹配的行号

    with open(input_file, "r") as file:
        for line_number, line in enumerate(file, start=1):  # 读取文件并获取行号
            if re.search(r"\bxor\b|\bxori\b", line, re.IGNORECASE):  # 查找 "xor" 或 "xori"
                # 提取类似 0x0005061e 的地址
                match = re.search(r"0x[0-9a-fA-F]+", line)
                if match:
                    address = int(match.group(0), 16)  # 转换为整数
                    # 跳过指定范围的地址
                    if skip_start <= address <= skip_end:
                        continue
                
                xor_lines.append(str(line_number))  # 记录行号

    # 将行号写入新的日志文件
    with open(output_file, "w") as out_file:
        out_file.write("\n".join(xor_lines) + "\n")

    print(f"Lines with 'xor' or 'xori' (excluding addresses in range) saved to {output_file}")

# 运行查找
find_xor_lines(input_file, output_file)
