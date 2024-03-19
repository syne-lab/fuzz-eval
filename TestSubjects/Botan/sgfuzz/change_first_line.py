import os

all_lines = []
with open("./Botan-2.17.3/configure.py", "r") as f:
    all_lines = f.readlines()

if("python3" not in all_lines[0]):
	all_lines[0] = all_lines[0].replace("python","python3")
with open("./Botan-2.17.3/configure.py", "w") as f:
    f.writelines(all_lines)
