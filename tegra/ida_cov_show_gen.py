import argparse

parser = argparse.ArgumentParser(
                    prog='ida_cov_show_gen.py',
                    description='Generate ida python scripts for coloring the covered basic blocks',
                    epilog='')

parser.add_argument('-c', '--cov_file')  
parser.add_argument('-o', '--out_file')

args = parser.parse_args()
color = 0x55ff55

# get all the covered basic block addresses
with open(args.cov_file, "r") as file:
    addresses = []
    address_lines = file.readlines()
    for addr in address_lines:
        if len(addr[:-1]) > 0:
            addresses.append(addr[:-1])

with open(args.out_file, "w") as file:
    file.write("import ida_bytes\n")
    file.write("def set_color(address, color):\n")
    file.write("\tida_bytes.set_color(address, ida_bytes.CIC_ITEM, color)\n")
    file.write("\n")
    for addr in addresses:
        file.write(f"set_color({addr}, {color})\n")
