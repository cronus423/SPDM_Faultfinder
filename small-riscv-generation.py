def generate_riscv_file(xor_lines_file, output_file):
    # 读取 xor_lines.log 并提取指令编号
    with open(xor_lines_file, "r") as file:
        instruction_lines = [line.strip() for line in file if line.strip().isdigit()]  # 只保留数字行
    start_index = 381
    end_index = 760  # Next 1/50 segment
    # 生成 small-riscv.txt 格式内容
    with open(output_file, "w") as file:
        for instruction in instruction_lines[start_index:end_index]:
            file.write(f"Instructions: {instruction}-{instruction}\n")
            file.write("    Registers-force: x15\n")
            file.write("        Op_codes: xor\n")
            file.write("            Lifespan: 0\n")
            file.write("                Operations: xOR\n")
            file.write("                    Masks:1<0<16\n\n")  # 每个指令块之间空行

    print(f"Generated {output_file} successfully.")

# 文件路径
xor_lines_file = "xor_lines_without_hash.log"
output_file = "small-riscv.txt"

# 运行函数生成文件
generate_riscv_file(xor_lines_file, output_file)

