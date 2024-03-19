import os

all_lines = []
with open("./matrixssl-4-3-0-open/core/makefiles/detect-and-rules.mk", "r") as f:
    all_lines = f.readlines()

if("build" not in all_lines[-1]):
	all_lines[-1] = all_lines[-1].replace("-o $@ $<","-o ./build/$@ $<")
with open("./matrixssl-4-3-0-open/core/makefiles/detect-and-rules.mk", "w") as f:
    f.writelines(all_lines)
