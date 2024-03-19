from subprocess import run, PIPE
from io import StringIO
from pprint import pprint
import itertools, sys
import operator, functools
import random, os, time
import hashlib, math
import multiprocessing as mp
import signal
from functools import partial
from datetime import datetime
import socket
PORT=8888
SEED=1000
def send_to_server(generated):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', PORT)

    # print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)
    try:

        # Send data
        message = generated.encode('ascii')
        print('sending {!r}'.format(message))
        sock.sendall(message)
        time.sleep(0.1)
    finally:
        # print('closing socket')
        sock.close()

M = b'hello world!'

N = 0xE932AC92252F585B3A80A4DD76A897C8B7652952FE788F6EC8DD640587A1EE5647670A8AD4C2BE0F9FA6E49C605ADF77B5174230AF7BD50E5D6D6D6D28CCF0A886A514CC72E51D209CC772A52EF419F6A953F3135929588EBE9B351FCA61CED78F346FE00DBB6306E5C2A4C6DFC3779AF85AB417371CF34D8387B9B30AE46D7A5FF5A655B8D8455F1B94AE736989D60A6F2FD5CADBFFBD504C5A756A2E6BB5CECC13BCA7503F6DF8B52ACE5C410997E98809DB4DC30D943DE4E812A47553DCE54844A78E36401D13F77DC650619FED88D8B3926E3D8E319C80C744779AC5D6ABE252896950917476ECE5E8FC27D5F053D6018D91B502C4787558A002B9283DA7

e = 3

d = 0x009b771db6c374e59227006de8f9c5ba85cf98c63754505f9f30939803afc1498eda44b1b1e32c7eb51519edbd9591ea4fce0f8175ca528e09939e48f37088a07059c36332f74368c06884f718c9f8114f1b8d4cb790c63b09d46778bfdc41348fb4cd9feab3d24204992c6dd9ea824fbca591cd64cf68a233ad0526775c9848fafa31528177e1f8df9181a8b945081106fd58bd3d73799b229575c4f3b29101a03ee1f05472b3615784d9244ce0ed639c77e8e212ab52abddf4a928224b6b6f74b7114786dd6071bd9113d7870c6b52c0bc8b9c102cfe321dac357e030ed6c580040ca41c13d6b4967811807ef2a225983ea9f88d67faa42620f42a4f5bdbe03b

N_len = len(hex(N)[2:]) // 2

hM = hashlib.sha256(M).hexdigest()

TARGET_HASH_ID = ('sha256', '256')

TARGET_RES_PREFIX = 'ret ='

ORACLE_PATH = '/morpheus/fvi-coq/oracle' 

ORACLE_RESULT_MAP = {'true': '0',
                     'false': '-1'}


HASH_ID = {'sha1':   '2b0e03021a',
           'sha224': '608648016503040204',
           'sha256': '608648016503040201',
           'sha384': '608648016503040202',
           'sha512': '608648016503040203'}

HASH_LEN = {'sha1':   20, 
            'sha224': 28,
            'sha256': 32,
            'sha384': 48,
            'sha512': 64}

MIN_NUM_COMPONENT_HIDING = 2  # Minimum number of components we target at the same time. If None, it'll be 1
MAX_NUM_COMPONENT_HIDING = 2  # Maximum number of components we target at the same time. If None, it'll be all 


SHORT_VERSION = True    # If True, only generate test cases for length 1 and correct length of component
ONLY_RANDOM = False     # If False, it also includes VOI
MIN_NUM_RANDOM_BYTE = 1 # Minimum number of random bytes injected (i.e., min length of random bytes)
MAX_NUM_RANDOM_BYTE = 3 # Maximum number of random bytes injected (i.e., max length of random bytes)
RANDOM_PER_LENGTH = 1   # Number different randoms per each length
APPEND_RANDOM = True    # If True, it also includes the cases where random bytes injected after the correct value
PREPEND_RANDOM = True   # If True, it also includes the cases where random bytes injected before the correct value


def dec_to_hex(value):
    """
    This function takes a decimal value as input and 
    returns hex string omitting the initial '0x'.
    """
    return hex(value)[2:].zfill(2).lower()

VOI = {'leading_byte': ['01','ff'], 
       'block_type': ['00','02'], 
       'padding_bytes': ['01','00','ff'], 
       'padding_end': ['01','ff','30'], 
       'asb@type': [e for e in list(map(dec_to_hex, list(range(1,49)))) if e != '30'], 
       'asb@length': list(map(dec_to_hex, list(range(87)))), 
       'hash_algo@type': [e for e in list(map(dec_to_hex, list(range(1,49)))) if e != '30'], 
       'hash_algo@length': list(map(dec_to_hex, list(range(18)))), 
       'hash_id@type': [e for e in list(map(dec_to_hex, list(range(1,49)))) if e != '06'], 
       'hash_id@length': list(map(dec_to_hex, list(range(11)))), 
       'hash_id@value': [e for e in list(HASH_ID.values()) if e != HASH_ID[TARGET_HASH_ID[0]]], 
       'param@type': [e for e in list(map(dec_to_hex, list(range(1,49)))) if e != '05'], 
       'param@length': list(map(dec_to_hex, [1,2])), 
       'hash_value@type': [e for e in list(map(dec_to_hex, list(range(1,49)))) if e != '04'], 
       'hash_value@length': list(map(dec_to_hex, list(set([0,1]).union(set(HASH_LEN.values())).union(set(list(map(lambda x: x + 1, HASH_LEN.values()))))))), 
       'hash_value@value': list(map(dec_to_hex, list(range(6))))}



def hex_to_list(hex_str):
    if hex_str[:2].lower() == '0x':
        hex_str = hex_str[2:]

    return [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]

def generate_signature(tbs):
    
    S = pow(int(tbs, 16), d, N)
 
    return hex(S)[2:].zfill(N_len * 2)


def exec(path, args, stdin=bytes()):
    """
    This function takes path and args as input and 
    return the executed program object
    """
    return run([path] + args, stdout=PIPE, stderr=PIPE, input=stdin)


def generate_pkcs1_structure(hash_value, hash_alg, explicit, size):
    """
    This function generates correct pkcs1 v1.5 structure as well
    as a component info object to indicate the start byte and 
    length of each component in bytes.
    """
    component_info = {}
    
    param_type = ""
    param_len = ""
    param_total_size = 0

    if explicit:
        param_type = "05"
        param_len = "00"
        param_total_size = 2
    
    l3 = len(HASH_ID[hash_alg]) // 2
    l2 = l3 + param_total_size + 2
    assert (len(hash_value) // 2) == HASH_LEN[hash_alg]
    l4 = len(hash_value) // 2
    l1 = l2 + l4 + 4
    
    sig_prefix = "30" \
    + dec_to_hex(l1) \
    + "30" \
    + dec_to_hex(l2) \
    + "06" \
    + dec_to_hex(l3) \
    + HASH_ID[hash_alg] \
    + param_type + param_len \
    + "04" \
    + dec_to_hex(l4)
    
    content_len = len(sig_prefix) // 2 + len(hash_value) // 2
    extra_padding_len = size - 11 - content_len


    pkcs1_tbs = "00" \
    + "01" \
    + "ff" * 8 \
    + "ff" * extra_padding_len \
    + "00" \
    + sig_prefix \
    + hash_value

    component_info['leading_byte'] = {'start': 0, 'length': 1}
    component_info['block_type'] = {'start': 1, 'length': 1}
    component_info['padding_bytes'] = {'start': 2, 'length': 8 + extra_padding_len}
    component_info['padding_end'] = {'start': 10 + extra_padding_len, 'length': 1}
    component_info['asb@type'] = {'start': 11 + extra_padding_len, 'length': 1}
    component_info['asb@length'] = {'start': 12 + extra_padding_len, 'length': 1}
    component_info['hash_algo@type'] = {'start': 13 + extra_padding_len, 'length': 1}
    component_info['hash_algo@length'] = {'start': 14 + extra_padding_len, 'length': 1}
    component_info['hash_id@type'] = {'start': 15 + extra_padding_len, 'length': 1}
    component_info['hash_id@length'] = {'start': 16 + extra_padding_len, 'length': 1}
    component_info['hash_id@value'] = {'start': 17 + extra_padding_len, 'length': l3}
    if explicit:
        component_info['param@type'] = {'start': 17 + extra_padding_len + l3, 'length': 1}
        component_info['param@length'] = {'start': 18 + extra_padding_len + l3, 'length': 1}
        component_info['hash_value@type'] = {'start': 19 + extra_padding_len + l3, 'length': 1}
        component_info['hash_value@length'] = {'start': 20 + extra_padding_len + l3, 'length': 1}
        component_info['hash_value@value'] = {'start': 21 + extra_padding_len + l3, 'length': l4}
    else:
        component_info['hash_value@type'] = {'start': 17 + extra_padding_len + l3, 'length': 1}
        component_info['hash_value@length'] = {'start': 18 + extra_padding_len + l3, 'length': 1}
        component_info['hash_value@value'] = {'start': 19 + extra_padding_len + l3, 'length': l4}

    return pkcs1_tbs, component_info

def get_component(label, pkcs1_tbs, component_info):
    """
    This function returns a hexstring representing the requested
    component (by given label). 
    """
    try:
        return pkcs1_tbs[component_info[label]['start']*2:component_info[label]['start']*2 + component_info[label]['length']*2]
    except:
        return None

def ncr(n, r):
    return list(itertools.combinations(n, r))


def generate_random_value(interest_values):
    """
    This method returns a random value. If interest values list
    is given, the random value will be selected based on that;
    otherwise, it will be selected as a number between 0 to 255.
    """
    random.seed(SEED) # numan947: do not reinintalize random, fix it from the code
    if interest_values:
        return interest_values[random.randrange(0, len(interest_values), 1)]
    else:
        return dec_to_hex(random.randrange(0, 256, 1))


def generate_random_string(length, interest_values):
    return ''.join([generate_random_value(interest_values) for i in range(length)])

def generate_testcases(label, pkcs1_tbs, component_info):
    testcases = {}
    component_correct_value = get_component(label, pkcs1_tbs, component_info)
    #testcases[label + '#correct'] = component_correct_value
    if label != 'leading_byte':
        testcases[label + '#null'] = ''
    if not isinstance(VOI[label][0], list):
        for l in range(component_info[label]['length']):
            c = 0
            if SHORT_VERSION: # only generate testcases given VOI for length 1 and length of component 
                if l != 0 and l + 1 != component_info[label]['length']: 
                    continue
            
            if not ONLY_RANDOM:
                # generate testcase for each member of VOI with length l + 1 (i.e., from 1 to length of component) 
                for i in range(len(VOI[label])):
                    tc = ''.join([VOI[label][i] for j in range(l + 1)])
                    if tc not in testcases.values() and tc != component_correct_value:
                        testcases[label + '#interest_' + str(c).zfill(3) + '_with_len_' + str(l + 1).zfill(3)] = tc
                        c = i + 1
                
                # generate testcase by mixing member of VOI with length l + 1, staring from length 2
                if l != 0:
                    tc = generate_random_string(l + 1, VOI[label])
                    if tc not in testcases.values() and tc != component_correct_value:
                        testcases[label + '#interest_' + str(c).zfill(3) + '_with_len_' + str(l + 1).zfill(3)] = tc
            

    else:
        if len(VOI[label][0]) == component_info[label]['length']:
            for i in range(len(VOI[label])):
                tc = ''.join(VOI[label][i])
                if tc not in testcases.values() and tc != component_correct_value:
                    testcases[label + '#interest_' + str(i).zfill(3)] = tc 

    for l in range(MIN_NUM_RANDOM_BYTE, MAX_NUM_RANDOM_BYTE + 1):
        for t in range(RANDOM_PER_LENGTH):
            tc = generate_random_string(l, None)
            if tc not in testcases.values() and tc != component_correct_value:
                testcases[label + '#random_' + str(t).zfill(3) + '_with_len_' + str(l).zfill(3)] = tc
                if APPEND_RANDOM:
                    testcases[label + '#random_append' + str(t).zfill(3) + '_with_len_' + str(l).zfill(3)] = component_correct_value + tc
            
                if PREPEND_RANDOM:
                    testcases[label + '#random_prepend' + str(t).zfill(3) + '_with_len_' + str(l).zfill(3)] = tc + component_correct_value
    testcases[label + '#extended_tag_0x1f' ] = '1f' + component_correct_value
    testcases[label + '#long_form_length_0x81' ] = '81' + component_correct_value

    return testcases

def prepare_testcases(label_tuple, pkcs1_tbs, component_info):
    testcases = {}
    
    for label in label_tuple:
        testcases[label] = generate_testcases(label, pkcs1_tbs, component_info)

    return testcases

def get_candidate_testcases(label_tuple, testcases_seed):
    candidate_testcases = {}

    for key, value in testcases_seed.items():
        if key in label_tuple:
            candidate_testcases[key] = value


    return candidate_testcases

def oracle(args):
    oracle_prog = exec(ORACLE_PATH, args)
    oracle_res = oracle_prog.stderr.decode('UTF-8').strip().lower()
    return ORACLE_RESULT_MAP[oracle_res]
       
def initial_sanity_check(correct_pkcs1, target_path, args):
    oracle_args_list = [correct_pkcs1] + args
    signature = generate_signature(correct_pkcs1)
    target_args_list = [signature] #+ [str(N_len)]
    
    target_prog = exec(target_path, target_args_list)

    target_output_not_expected = False
    try:
        target_output = target_prog.stdout.decode('UTF-8').strip().lower().split(TARGET_RES_PREFIX)[1].strip()
        if target_output != '0':
            target_output = '-1'
    except:
        target_output_not_expected = True
        target_output = target_prog.stdout.decode('UTF-8').strip()

    target_retcode = target_prog.returncode

    oracle_output = oracle(oracle_args_list)
    
    output_result = ''

    if target_output != oracle_output and not target_output_not_expected:
        output_result += '>>>>> Mismatch found!\n'

    if target_retcode !=0 and target_output_not_expected:
        output_result += '>>>>> Error found!\n'

    if target_output != oracle_output or (target_retcode != 0 and target_output_not_expected):
        output_result += '$$$$$ Initial sanity check has failed\n'
    else:
        output_result += '##### Initial sanity check has passed successfully\n'

    output_result += '* Correct PKCS1 String: {}\n'.format(correct_pkcs1)
    output_result += '* Correct Signature String: {}\n'.format(signature)
    output_result += '* Oracle Cmd: {} {}\n'.format(ORACLE_PATH, ' '.join(oracle_args_list))
    output_result += '* Oracle Output: {}\n'.format(oracle_output)
    output_result += '* Target Cmd: {} {}\n'.format(target_path, ' '.join(target_args_list))
    output_result += '* Target Output: {}\n'.format(target_output)
    output_result += '* Target stdout: {}\n\n'.format(target_prog.stdout.decode('UTF-8').strip())
    output_result += '* Target stderr: {}\n\n'.format(target_prog.stderr.decode('UTF-8').strip())

    print(output_result) if output_result != '' else None


def launch_fuzzer(testcases_pool, target_path, args):
    for element in itertools.product(*testcases_pool):
        i = 0
        testcase_name = '|'.join(list(element))
        testcase_string = ''
        for key in list(element):
            testcase_string += testcases_pool[i][key]
            i += 1
        
        if int(testcase_string, 16) >= N or testcase_string[:4] == '01ff':
            continue

        oracle_args_list = [testcase_string] + args
        signature = generate_signature(testcase_string)    
        target_args_list = [signature] #+ [str(N_len)]
        
        target_prog = exec(target_path, target_args_list)

        target_output_not_expected = False
        try:
            target_output = target_prog.stdout.decode('UTF-8').strip().lower().split(TARGET_RES_PREFIX)[1].strip()
            if target_output != '0':
                target_output = '-1'
        except:
            target_output_not_expected = True 
            target_output = target_prog.stdout.decode('UTF-8').strip()
        
        target_retcode = target_prog.returncode
        
        send_to_server(testcase_string+","+target_output)

        oracle_output = oracle(oracle_args_list)
        
        output_result = ''

        if target_output != oracle_output and not target_output_not_expected:
            output_result += '>>>>> Mismatch found!\n'

        if target_retcode !=0 and target_output_not_expected:
            output_result += '>>>>> Error found!\n'
        
        if target_output != oracle_output or (target_retcode != 0 and target_output_not_expected):
            root_cause = '|'.join(list(filter(lambda x: '#correct' not in x, testcase_name.split('|'))))
            output_result += '* Category: {}\n'.format(testcase_name)
            output_result += '* Root cause: {}\n'.format(root_cause)
            output_result += '* Testcase String: {}\n'.format(testcase_string)
            output_result += '* Signature String: {}\n'.format(signature)
            output_result += '* Oracle Cmd: {} {}\n'.format(ORACLE_PATH, ' '.join(oracle_args_list))
            output_result += '* Oracle Output: {}\n'.format(oracle_output)
            output_result += '* Target Cmd: {} {}\n'.format(target_path, ' '.join(target_args_list))
            output_result += '* Target Output: {}\n'.format(target_output)
            output_result += '* Target stdout: {}\n'.format(target_prog.stdout.decode('UTF-8').strip())
            output_result += '* Target stderr: {}\n'.format(target_prog.stderr.decode('UTF-8').strip())
            output_result += '* Target Return Code: {}\n\n\n\n'.format(target_retcode)
        
        print(output_result) if output_result != '' else None

def calculate_total_testcases(testcases_seed):
    total_no = 0
    components = testcases_seed.keys()
    for r in range(MIN_NUM_COMPONENT_HIDING, MAX_NUM_COMPONENT_HIDING + 1): # For each number of combinations
        subset_list = ncr(set(components), r)
        for c in range(len(subset_list)): # For each selected combination
            candidate_testcases = get_candidate_testcases(subset_list[c], testcases_seed)
            num = 1
            for key, value in candidate_testcases.items():
                num *= len(value)
            total_no += num
    return total_no


def signal_handler(start_dt, signum, frame):
    now_dt = datetime.now()
    elapsed_dt = now_dt - start_dt
    print('Exit requested at {}'.format(now_dt))
    print('Elapsed time: {}'.format(elapsed_dt))
    sys.exit(0)


def main():
    global MAX_NUM_COMPONENT_HIDING
    global MIN_NUM_COMPONENT_HIDING
    global PORT #numan947
    if len(sys.argv) != 5:
        print('usage: python3 {} <target_binary> <exp/imp> <port> <RNG SEED>'.format(sys.argv[0]))
        exit(1)
    
    if not os.path.exists(sys.argv[1]):
        print('Target binary cannot be found at "{}"'.format(sys.argv[1]))
        print('You should specify fully qualified file name of the target binary.')
        exit(1)
    
    if sys.argv[2].lower() != 'exp' and sys.argv[2].lower() != 'imp':
        print('Input structure type for this fuzz test should be "exp" or "imp" for explicit or implicit cases, resp.')
        exit(1)

    args = [str(N_len)] + [hM] + [TARGET_HASH_ID[1]]
    PORT = int(sys.argv[3]) # numan947
    SEED = int(sys.argv[4]) # numan947
    components = None
    exp = sys.argv[2].lower() == 'exp'
    if exp:
        components = ('leading_byte', 'block_type', 'padding_bytes', 'padding_end', 'asb@type', 'asb@length', 'hash_algo@type', 'hash_algo@length', 'hash_id@type', 'hash_id@length', 'hash_id@value', 'param@type', 'param@length', 'hash_value@type', 'hash_value@length', 'hash_value@value')
    else:
        components = ('leading_byte', 'block_type', 'padding_bytes', 'padding_end', 'asb@type', 'asb@length', 'hash_algo@type', 'hash_algo@length', 'hash_id@type', 'hash_id@length', 'hash_id@value', 'hash_value@type', 'hash_value@length', 'hash_value@value')
    
    pkcs1_tbs, component_info = generate_pkcs1_structure(hM, TARGET_HASH_ID[0], exp, N_len)
    
    testcases_seed = prepare_testcases(components, pkcs1_tbs, component_info)
    
    if MAX_NUM_COMPONENT_HIDING == None:
        MAX_NUM_COMPONENT_HIDING = len(components)

    if MIN_NUM_COMPONENT_HIDING == None:
        MIN_NUM_COMPONENT_HIDING = 1

    assert MAX_NUM_COMPONENT_HIDING > 0 and MAX_NUM_COMPONENT_HIDING <= len(components)
    assert MIN_NUM_COMPONENT_HIDING > 0 and MIN_NUM_COMPONENT_HIDING <= len(components)
    assert MIN_NUM_COMPONENT_HIDING <= MAX_NUM_COMPONENT_HIDING

    total_tc = calculate_total_testcases(testcases_seed)
    print('Total number of testcases = {}\n'.format(total_tc))
    
    initial_sanity_check(pkcs1_tbs, sys.argv[1], args)
   
    start_dt = datetime.now()

    print('Fuzzing started at {}'.format(datetime.now()))
    
    signal.signal(signal.SIGINT, partial(signal_handler, start_dt))
    signal.signal(signal.SIGTSTP, partial(signal_handler, start_dt))

    print('It will take long time; please be patient. You can do Ctrl-z to exit the fuzzer whenever you want.\n')
    
    print('-'*20, 'Begin: testcases seed', '-'*20)
    pprint(testcases_seed)
    print('-'*20, 'End: testcases seed', '-'*20, '\n\n\n')

    for r in range(MIN_NUM_COMPONENT_HIDING, MAX_NUM_COMPONENT_HIDING + 1): # For each number of combinations
        subset_list = ncr(set(components), r)
        for c in range(len(subset_list)): # For each selected combination
            candidate_testcases = get_candidate_testcases(subset_list[c], testcases_seed)
            index = 0
            pindex = -1
            pcomp = ''
            testcases_pool = []
            for component in components:
                if component in candidate_testcases:
                    if pindex == -1: # Parallelization angel found
                        pindex = index
                        pcomp = component
                    else:
                       testcases_pool.append(candidate_testcases[component])

                else:
                    correct_testcase = {}
                    component_correct_value = get_component(component, pkcs1_tbs, component_info)
                    correct_testcase[component + '#correct'] = component_correct_value
                    testcases_pool.append(correct_testcase)
                
                index += 1
            
            # sanity check
            assert pindex != -1 and pcomp != ''
           
            pool = mp.Pool()

            for key, value in candidate_testcases[pcomp].items():
                testcase = {}
                testcase[key] = value
                batch = testcases_pool[:pindex] + [testcase] + testcases_pool[pindex:]
                pool.apply_async(launch_fuzzer, [batch] + [sys.argv[1]] + [args])
            pool.close()
            pool.join()
    
    
    now_dt = datetime.now()
    elapsed_dt = now_dt - start_dt
    print('Finished at {}'.format(now_dt))
    print('Elapsed time: {}'.format(elapsed_dt))


if __name__ == "__main__":
    main()
    


