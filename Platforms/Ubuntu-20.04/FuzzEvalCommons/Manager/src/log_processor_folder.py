import os
import argparse

def printLog(logfile):
    
    lines = None
    with open(logfile, "r") as f:
        lines = f.readlines()
    
    total = len(lines)
    print(total)
    total_valid = 0
    valid_actual = 0
    valid_harness = 0
    invalid = 0
    for i, l in enumerate(lines):
        tt = l.split(",")
        
        if(len(tt) == 3):
            invalid+=1
            # print(l)
            # print(i)
            continue
        total_valid+=1
        if(int(tt[-2]) == 1):
            valid_harness += 1
        if(int(tt[-1]) == 1):
            valid_actual += 1

    print("INVALID: ", invalid, "%({})".format(100.0*invalid/total))
    print("TOTAL: ", total)
    print("Valid Harness: ", valid_harness, " % = ", 100.0*valid_harness/total_valid)
    print("Valid Actual: ", valid_actual, " % = ", 100.0*valid_actual/total_valid)
        


def main():
    
    parser = argparse.ArgumentParser(description="Input Quality Validator for PKCS#1 v1.5 encoded files")
    parser.add_argument("-lp", '--logfolder', help='Logfolder path', required=True)
    parser.add_argument("-p", '--prefix', help='Logfolder prefix', required=True)
    args = vars(parser.parse_args())
    # print(os.listdir(args['logfolder']))
    
    for f in os.listdir(args['logfolder']):
        ff =  str(f)
        if(ff.startswith(args['prefix'])):
            print("Analyzing: ", ff)
            for dd in os.listdir(args['logfolder']+os.sep+ff):
                if('debug' not in dd):
                    printLog(args['logfolder']+os.sep+ff+os.sep+dd)
            print("-------------------------------")
    
    # printLog(args['logpath'])

if __name__ == '__main__':
    main()