import filecmp
import os
import argparse
import pathlib
import toml

def isValid(data, modulussize):
    # print("HELLO WORLD")
    # trivial checks
    # print(len(data))
    if(len(data) != modulussize):
        # print("Length Problem")
        return False
    if(data[0] != 0x00):
        return False
    if(data[1] != 0x01):
        return False
    
    padding_count = 0
    idx = 2
    while(idx < len(data)):
        if(data[idx] == 0xFF): # valid padding bytes
            padding_count+=1
            idx+=1
        elif(data[idx] == 0x00): # padding finished
            idx+=1
            break
        else:
            return False # anything else in padding is not allowed
    
    data_bytes_count = len(data[idx:])
    
    if(padding_count<8):
        return False
    
    return modulussize == (padding_count+data_bytes_count+3)

def main():
    
    parser = argparse.ArgumentParser(description="Input Quality Validator for PKCS#1 v1.5 encoded files")
    parser.add_argument("-d", '--dir', help='Folder of the generated inputs', required=True)
    parser.add_argument("-ms", '--modulussize', help='Modulus size in bits', default=512)
    parser.add_argument("-sf", '--savefilename', help='Save File Name', default="stats.toml")
    args = vars(parser.parse_args())
    
    save_file = args["savefilename"]
    input_dir = args["dir"]
    list1 = []
    for filepath in pathlib.Path(args['dir']).glob('**/*'):
        list1.append(filepath.absolute())
        
    print("Total_Files = ",len(list1))
    
    toml_dict = {}
    toml_dict["Total_files"] = len(list1)
    
    vc = 0
    modulussize = int(args['modulussize'])/8
    
    valid_list = []
    for fp in list1:
        with open(fp, "rb") as f:
            data = f.read()
            if(isValid(data, modulussize)):
                valid_list.append(str(fp).split("/")[-1])
                vc+=1
            
    
    # valid_list.sort()
    with open("ff.txt", "w") as f:
        print(valid_list, file=f)
    
    toml_dict["Valid_count"] = vc
    toml_dict["Valid_percentage"] = 100.0*vc/len(list1)
    print("Valid Count: ", vc)
    print("Valid Percentage: ", 100.0*vc/len(list1))
    
    with open(input_dir+"/../"+save_file, "w") as f:
        toml.dump(toml_dict, f)
    
    

if __name__ == '__main__':
    main()