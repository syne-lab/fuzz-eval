import toml
import filecmp
import os
import argparse
import pathlib
import sys
import glob
import shutil
import subprocess
import socket
import time
from execute import execute, Timeout



def stop_server(config):
    SERVER_PORT=int(config['server_port'])
    SERVER_STOP_COMMAND=str(config['server_stop_command'])
    s = socket.socket()
    s.connect(("localhost", SERVER_PORT))
    s.send(SERVER_STOP_COMMAND.encode())
    s.close()

def start_server(config, log_file_name):
    global ENV_VARS
    SERVER_PORT=str(config['server_port'])
    SERVER_LOG_FILE_PREFIX=config['server_log_file_prefix']
    SERVER_BACKLOG=str(config['server_backlog'])
    SERVER_STOP_COMMAND=str(config['server_stop_command'])
    
    python_to_use = "python3"
    
    if "USEDPYTHON" in os.environ.keys():
        python_to_use = os.environ["USEDPYTHON"]
    subprocess.Popen(["{}".format(python_to_use), SERVER_PATH,"-lp", FC_DIR+"/"+SERVER_LOG_FILE_PREFIX+log_file_name, '-p', SERVER_PORT, "-bl", SERVER_BACKLOG, "-sc", SERVER_STOP_COMMAND, "-ts"])


def run_fuzzer(config, rng_val):
    global ENV_VARS
    FUZZER_COMMAND = config['fuzzer_command']
    print("init: ",FUZZER_COMMAND)
    fuzz_time = 30 # default to 30 seconds
    use_execute = True
    
    if('fuzzer_fuzztime' in config.keys()):
        fuzz_time = config['fuzzer_fuzztime']
        if("FUZZTIME" in FUZZER_COMMAND):
            use_execute = False
            FUZZER_COMMAND = FUZZER_COMMAND.replace("FUZZTIME", str(fuzz_time))

    if('fuzzer_out_dir_name' in config.keys()):
        fuzzer_out_dir=RESULTS_DIR+"/"+config['fuzzer_out_dir_name']
        shutil.rmtree(fuzzer_out_dir, ignore_errors=True) # removing old directory, no need to save these
        FUZZER_COMMAND = FUZZER_COMMAND.replace("OUTDIR", str(fuzzer_out_dir))
        os.makedirs(fuzzer_out_dir)
    
    if('fuzzer_seed_dir' in config.keys()):
        fuzzer_seed_dir = config['fuzzer_seed_dir']
        FUZZER_COMMAND = FUZZER_COMMAND.replace("SEEDDIR", str(fuzzer_seed_dir))
    
    if('fuzzer_harness_timeout' in config.keys()):
        fuzzer_harness_timeout = config['fuzzer_harness_timeout']
        FUZZER_COMMAND = FUZZER_COMMAND.replace("TIMEOUT", str(fuzzer_harness_timeout))
    
    if('fuzzer_harness_path' in config.keys()):
        fuzzer_harness_path = config['fuzzer_harness_path']
        FUZZER_COMMAND = FUZZER_COMMAND.replace("HARNESSPATH", str(fuzzer_harness_path))
    
    if('server_port' in config.keys()):
        serverport = config['server_port']
        FUZZER_COMMAND = FUZZER_COMMAND.replace("PORT", str(serverport))
    
    if('fuzzer_dict_path' in config.keys()):
        fuzzer_dict_path = str(config['fuzzer_dict_path'])
        FUZZER_COMMAND = FUZZER_COMMAND.replace("FUZZERDICT", fuzzer_dict_path)
    
    if(rng_val is not None):
        FUZZER_COMMAND = FUZZER_COMMAND.replace("RNG", str(rng_val))
    
    
    if('fuzzer_fuzztime' not in config.keys()):
        print("fuzz time is not specified, fuzzing for 30 seconds!")
    
    print("RUNNING....")
    FUZZER_COMMAND = os.path.expandvars(FUZZER_COMMAND)
    print(FUZZER_COMMAND)
    if(use_execute):
        print("FUZZTIME not in FUZZER_COMMAND, using execute()")
        run_stat = execute(FUZZER_COMMAND, fuzz_time)
    else:
        print("using subprocess.run()")
        subprocess.run(FUZZER_COMMAND, shell=True)
        
    # print(run_stat)


def setup_environments(config):
    global ENV_VARS
    if('ENV_VARS' not in config.keys()): # not always necessary to setup environments
        ENV_VARS = {}
        return


    env_vars = config['ENV_VARS']
    if("PATH" in env_vars.keys()):
        os.environ["PATH"]+=os.pathsep+os.pathsep.join(env_vars["PATH"])
        del env_vars["PATH"]
    
    for k, v in ENV_VARS.items():
        os.environ[k] = v
    for k, v in os.environ.items():
        print(k,"=",v)
    
    # print(os.environ)
    

def do_fuzzing(log_file_name, configDict, rng_val = None):
    
    log_file_name = FC_NAME+log_file_name+".log"
    
    print("Setting up environment variables")
    setup_environments(config=configDict)
    
    try:
        print("STARTING SERVER, logfile = {}".format(log_file_name))
        start_server(configDict, log_file_name)
    except Exception as e:
        print("Failed to start the server -->", str(e))
    time.sleep(2)
    
    try:
        run_fuzzer(configDict, rng_val)
    except Exception as e:
        if(isinstance(e, Timeout)):
            print("Fuzzing Run Completed!")
        else:
            # stop_server(configDict)
            print("RUN FUZZER EXCEPTION-->", str(e))
            
    time.sleep(2)
    
    print("STOPPING SERVER, logfile = {}".format(log_file_name))
    stop_server(configDict)
    time.sleep(2)
    # print(os.environ)





SRCDIR_PATH=""
SERVER_PATH=""
FC_DIR=""
RESULTS_DIR=""
FC_NAME = ""
ENV_VARS = {}

def main():
    
    global SRCDIR_PATH
    global SERVER_PATH
    global FC_DIR
    global RESULTS_DIR
    global ENV_SETUP_COMMANDS
    global FC_NAME
    
    SRCDIR_PATH = str(pathlib.Path(__file__).parent.resolve())
    SERVER_PATH = SRCDIR_PATH+"/server/server.py"
    if(os.path.isfile(SERVER_PATH) == False):
        print("server.py not found")
    
    
    parser = argparse.ArgumentParser(description="Run fuzzing campaign.")
    parser.add_argument("-c", '--configpath', help='Path to the config file', required=True)
    args = vars(parser.parse_args())
    configpath = args['configpath']
    configpath = os.path.expandvars(configpath)
    configDict = {}
    with open(configpath, 'r') as f:
        configDict = toml.load(f)
    
    
    GLOBAL_CONFIG_PATH = str(pathlib.Path(configpath).parent.resolve())+"/global.toml"
    
    if(os.path.isfile(GLOBAL_CONFIG_PATH) == False):
        print("No Global Config Set....")
        print("Using Local Config....")
    else:
        print("Global Config Found! Overriding local config...")
        with open(GLOBAL_CONFIG_PATH, "r") as f:
            g_conf = toml.load(f)
            
            for k in g_conf.keys():
                if k in configDict.keys():
                    configDict[k] = g_conf[k]
    

    RESULTS_DIR=configDict['results_dir']
    pathlib.Path(RESULTS_DIR).mkdir(parents=True, exist_ok=True)
    
    FC_NAME = configDict['fc_name']
    
    FC_DIR=RESULTS_DIR+"/"+FC_NAME
    pathlib.Path(FC_DIR).mkdir(parents=True, exist_ok=True)
    
    
    if('rng_seedlist' in configDict.keys()):
        rng_list = configDict['rng_seedlist']
        for r in rng_list:
            do_fuzzing("-rng-seed-{}".format(r), configDict, r)
    else:
        do_fuzzing("-single-run", configDict)
    
    # print("HELLO WORLD")
    
    # print(configDict)
        
if __name__ == '__main__':
    main()