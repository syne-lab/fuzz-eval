from subprocess import run, PIPE
from io import StringIO
from pprint import pprint
import itertools, sys
import operator, functools
import random, os
import hashlib, math
import multiprocessing as mp
import signal
from functools import partial
from datetime import datetime

import socket
PORT=8888
def send_to_server(generated):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', PORT)

    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)
    try:

        # Send data
        message = generated.encode('ascii')
        print('sending {!r}'.format(message))
        sock.sendall(message)
    finally:
        print('closing socket')
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

COMPONENTS_SET = {'leading_byte', 'block_type', 'padding_bytes', 'padding_end', 'asb@type', 'asb@length', 'hash_algo@type', 'hash_algo@length', 'hash_id@type', 'hash_id@length', 'hash_id@value', 'param@type', 'param@length', 'param@value','hash_value@type', 'hash_value@length', 'hash_value@value'}

#STEAL_SET = {'padding_bytes'}
#STEAL_SET = {'hash_id@value'}
STEAL_SET = COMPONENTS_SET


MIN_NUM_BYTES_HIDING = 1    # Minimum number of bytes we hide as a result of stealing.
MAX_NUM_BYTES_HIDING = 220    # Maximum number of bytes we hide as a result of stealing. 

VOI = [0x88]

def ncr(n, r):
    return list(itertools.combinations(n, r))

def dec_to_hex(value):
    """
    This function takes a decimal value as input and 
    returns hex string omitting the initial '0x'.
    """
    return hex(value)[2:].zfill(2).lower()


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
        component_info['param@value'] = {'start': 19 + extra_padding_len + l3, 'length': 0}
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

def steal_bytes(num_bytes, label, pkcs1_tbs, component_info):
    try:
        if num_bytes > component_info[label]['length']:
            return None, None
        else:
            modified_pkcs1_tbs = pkcs1_tbs[:component_info[label]['start']*2] + pkcs1_tbs[(component_info[label]['start']*2) + (num_bytes * 2):]
            modified_component_info = {}
            for key, value in component_info.items():
                if component_info[key]['start'] < component_info[label]['start']:
                    comp = {}
                    comp['start'] = component_info[key]['start']
                    comp['length'] = component_info[key]['length']
                    modified_component_info[key] = comp
                elif component_info[key]['start'] == component_info[label]['start']:
                    if num_bytes <= component_info[label]['length']:
                        comp = {}
                        comp['start'] = component_info[key]['start']
                        comp['length'] = component_info[key]['length'] - num_bytes
                        modified_component_info[key] = comp
                else:
                    comp = {}
                    comp['start'] = component_info[key]['start'] - num_bytes
                    comp['length'] = component_info[key]['length']
                    modified_component_info[key] = comp
            return modified_pkcs1_tbs, modified_component_info
    except:
        return None, None


def inject_before(inject_hex_str, inject_label, label, pkcs1_tbs, component_info):
    try:
        modified_pkcs1_tbs = pkcs1_tbs[:component_info[label]['start']*2] + inject_hex_str + pkcs1_tbs[(component_info[label]['start']*2):]
        modified_component_info = {}
        comp = {}
        comp['start'] = component_info[label]['start']
        comp['length'] = len(inject_hex_str) // 2
        modified_component_info[inject_label] = comp
        for key, value in component_info.items():
            if component_info[key]['start'] < component_info[label]['start']:
                comp = {}
                comp['start'] = component_info[key]['start']
                comp['length'] = component_info[key]['length']
                modified_component_info[key] = comp
            else:
                comp = {}
                comp['start'] = component_info[key]['start'] + (len(inject_hex_str) // 2)
                comp['length'] = component_info[key]['length']
                modified_component_info[key] = comp
        return modified_pkcs1_tbs, modified_component_info
    except:
        return None, None


def inject(inject_hex_str, inject_label, label, position, pkcs1_tbs, component_info, tlv_adjustment=True):
    try:
        modified_pkcs1_tbs = pkcs1_tbs[:(component_info[label]['start']*2) + (position*2)] + inject_hex_str + pkcs1_tbs[(component_info[label]['start']*2) + (position*2):]
        modified_component_info = {}
        comp = {}
        comp['start'] = (component_info[label]['start']) + (position)
        comp['length'] = len(inject_hex_str) // 2
        modified_component_info[inject_label] = comp
        for key, value in component_info.items():
            if component_info[key]['start'] < component_info[label]['start']:
                comp = {}
                comp['start'] = component_info[key]['start']
                comp['length'] = component_info[key]['length']
                modified_component_info[key] = comp
            elif key == label:
                comp = {}
                comp['start'] = component_info[key]['start']
                comp['length'] = component_info[key]['length'] + len(inject_hex_str) // 2 if tlv_adjustment else component_info[key]['length']
                modified_component_info[key] = comp
            else:
                comp = {}
                comp['start'] = component_info[key]['start'] + (len(inject_hex_str) // 2)
                comp['length'] = component_info[key]['length']
                modified_component_info[key] = comp
        
        if tlv_adjustment:
            if label == 'hash_algo@type' or label == 'hash_value@type':
                asb_len_cur_val = int(modified_pkcs1_tbs[(modified_component_info['asb@length']['start']*2)] + modified_pkcs1_tbs[(modified_component_info['asb@length']['start']*2) + 1], 16)
                asb_len_cur_val += len(inject_hex_str) // 2
                asb_len_new_val = dec_to_hex(asb_len_cur_val)
                mpt_list = list(modified_pkcs1_tbs)
                mpt_list[(modified_component_info['asb@length']['start']*2)] = asb_len_new_val[0]
                mpt_list[(modified_component_info['asb@length']['start']*2) + 1] = asb_len_new_val[1]
                modified_pkcs1_tbs = "".join(mpt_list)
            
            elif label == 'hash_id@type' or label == 'param@type':
                halg_len_cur_val = int(modified_pkcs1_tbs[(modified_component_info['hash_algo@length']['start']*2)] + modified_pkcs1_tbs[(modified_component_info['hash_algo@length']['start']*2) + 1], 16)
                halg_len_cur_val += len(inject_hex_str) // 2
                halg_len_new_val = dec_to_hex(halg_len_cur_val)
                
                asb_len_cur_val = int(modified_pkcs1_tbs[(modified_component_info['asb@length']['start']*2)] + modified_pkcs1_tbs[(modified_component_info['asb@length']['start']*2) + 1], 16)
                asb_len_cur_val += len(inject_hex_str) // 2
                asb_len_new_val = dec_to_hex(asb_len_cur_val)
                
                mpt_list = list(modified_pkcs1_tbs)
                mpt_list[(modified_component_info['hash_algo@length']['start']*2)] = halg_len_new_val[0]
                mpt_list[(modified_component_info['hash_algo@length']['start']*2) + 1] = halg_len_new_val[1]
                mpt_list[(modified_component_info['asb@length']['start']*2)] = asb_len_new_val[0]
                mpt_list[(modified_component_info['asb@length']['start']*2) + 1] = asb_len_new_val[1]
                modified_pkcs1_tbs = "".join(mpt_list)

            elif label == 'hash_id@value':
                hid_len_cur_val = int(modified_pkcs1_tbs[(modified_component_info['hash_id@length']['start']*2)] + modified_pkcs1_tbs[(modified_component_info['hash_id@length']['start']*2) + 1], 16)
                hid_len_cur_val += len(inject_hex_str) // 2
                hid_len_new_val = dec_to_hex(hid_len_cur_val)
                
                halg_len_cur_val = int(modified_pkcs1_tbs[(modified_component_info['hash_algo@length']['start']*2)] + modified_pkcs1_tbs[(modified_component_info['hash_algo@length']['start']*2) + 1], 16)
                halg_len_cur_val += len(inject_hex_str) // 2
                halg_len_new_val = dec_to_hex(halg_len_cur_val)
                
                asb_len_cur_val = int(modified_pkcs1_tbs[(modified_component_info['asb@length']['start']*2)] + modified_pkcs1_tbs[(modified_component_info['asb@length']['start']*2) + 1], 16)
                asb_len_cur_val += len(inject_hex_str) // 2
                asb_len_new_val = dec_to_hex(asb_len_cur_val)
                
                mpt_list = list(modified_pkcs1_tbs)
                mpt_list[(modified_component_info['hash_id@length']['start']*2)] = hid_len_new_val[0]
                mpt_list[(modified_component_info['hash_id@length']['start']*2) + 1] = hid_len_new_val[1]
                mpt_list[(modified_component_info['hash_algo@length']['start']*2)] = halg_len_new_val[0]
                mpt_list[(modified_component_info['hash_algo@length']['start']*2) + 1] = halg_len_new_val[1]
                mpt_list[(modified_component_info['asb@length']['start']*2)] = asb_len_new_val[0]
                mpt_list[(modified_component_info['asb@length']['start']*2) + 1] = asb_len_new_val[1]
                modified_pkcs1_tbs = "".join(mpt_list)
        
            elif label == 'param@value':
                param_len_cur_val = int(modified_pkcs1_tbs[(modified_component_info['param@length']['start']*2)] + modified_pkcs1_tbs[(modified_component_info['param@length']['start']*2) + 1], 16)
                param_len_cur_val += len(inject_hex_str) // 2
                param_len_new_val = dec_to_hex(param_len_cur_val)
                
                halg_len_cur_val = int(modified_pkcs1_tbs[(modified_component_info['hash_algo@length']['start']*2)] + modified_pkcs1_tbs[(modified_component_info['hash_algo@length']['start']*2) + 1], 16)
                halg_len_cur_val += len(inject_hex_str) // 2
                halg_len_new_val = dec_to_hex(halg_len_cur_val)
                
                asb_len_cur_val = int(modified_pkcs1_tbs[(modified_component_info['asb@length']['start']*2)] + modified_pkcs1_tbs[(modified_component_info['asb@length']['start']*2) + 1], 16)
                asb_len_cur_val += len(inject_hex_str) // 2
                asb_len_new_val = dec_to_hex(asb_len_cur_val)
                
                mpt_list = list(modified_pkcs1_tbs)
                mpt_list[(modified_component_info['param@length']['start']*2)] = param_len_new_val[0]
                mpt_list[(modified_component_info['param@length']['start']*2) + 1] = param_len_new_val[1]
                mpt_list[(modified_component_info['hash_algo@length']['start']*2)] = halg_len_new_val[0]
                mpt_list[(modified_component_info['hash_algo@length']['start']*2) + 1] = halg_len_new_val[1]
                mpt_list[(modified_component_info['asb@length']['start']*2)] = asb_len_new_val[0]
                mpt_list[(modified_component_info['asb@length']['start']*2) + 1] = asb_len_new_val[1]
                modified_pkcs1_tbs = "".join(mpt_list)
        
            elif label == 'hash_value@value':
                hval_len_cur_val = int(modified_pkcs1_tbs[(modified_component_info['hash_value@length']['start']*2)] + modified_pkcs1_tbs[(modified_component_info['hash_value@length']['start']*2) + 1], 16)
                hval_len_cur_val += len(inject_hex_str) // 2
                hval_len_new_val = dec_to_hex(hval_len_cur_val)

                asb_len_cur_val = int(modified_pkcs1_tbs[(modified_component_info['asb@length']['start']*2)] + modified_pkcs1_tbs[(modified_component_info['asb@length']['start']*2) + 1], 16)
                asb_len_cur_val += len(inject_hex_str) // 2
                asb_len_new_val = dec_to_hex(asb_len_cur_val)

                mpt_list = list(modified_pkcs1_tbs)
                mpt_list[(modified_component_info['hash_value@length']['start']*2)] = hval_len_new_val[0]
                mpt_list[(modified_component_info['hash_value@length']['start']*2) + 1] = hval_len_new_val[1]
                mpt_list[(modified_component_info['asb@length']['start']*2)] = asb_len_new_val[0]
                mpt_list[(modified_component_info['asb@length']['start']*2) + 1] = asb_len_new_val[1]
                modified_pkcs1_tbs = "".join(mpt_list)

        return modified_pkcs1_tbs, modified_component_info
    except:
        return None, None

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

    print(output_result) if output_result != '' else None


def bug_detector(testcase_string, component_info, target_path, args):
    try:
        assert int(testcase_string, 16) < N
    except:
        print('assertion failed for testcase = {}'.format(testcase_string))
        exit(0)
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

    oracle_output = oracle(oracle_args_list)
    
    tmp_out = target_output
    if(target_output == '0'):
        tmp_out = '1'
    else:
        tmp_out = '0'
    send_to_server(testcase_string + ","+tmp_out)
    
    
    bug_detected = False

    if target_output != oracle_output and not target_output_not_expected:
        print('>>>>> Mismatch found!\n')

    if target_retcode !=0 and target_output_not_expected:
        print('>>>>> Error found!\n')
    
    if target_output != oracle_output or (target_retcode != 0 and target_output_not_expected):
        bug_detected = True
        root_cause = [{key: val} for key, val in component_info.items() if 'hidden_byte' in key] 
        print('* Testcase String: {}\n'.format(testcase_string))
        print('* Components Info:')
        pprint(component_info)
        print('\n* Root cause: {}\n'.format(root_cause))
        print('* Signature String: {}\n'.format(signature))
        print('* Oracle Cmd: {} {}\n'.format(ORACLE_PATH, ' '.join(oracle_args_list)))
        print('* Oracle Output: {}\n'.format(oracle_output))
        print('* Target Cmd: {} {}\n'.format(target_path, ' '.join(target_args_list)))
        print('* Target Output: {}\n'.format(target_output))
        print('* Target stdout: {}\n'.format(target_prog.stdout.decode('UTF-8').strip()))
        print('* Target stderr: {}\n'.format(target_prog.stderr.decode('UTF-8').strip()))
        print('* Target Return Code: {}\n\n\n\n'.format(target_retcode))
    
    return bug_detected

def signal_handler(start_dt, signum, frame):
    now_dt = datetime.now()
    elapsed_dt = now_dt - start_dt
    print('Exit requested at {}'.format(now_dt))
    print('Elapsed time: {}'.format(elapsed_dt))
    sys.exit(0)

def binary_search(low, high, pkcs1_tbs, component_info, st_label, comp, i, rand_str, target_path, args, before_inject=False, tlv_adjustment=True):
    while low <= high:
        mid = (low + high) // 2
       
        mid_res = False
        modified_pkcs1_tbs, modified_component_info = steal_bytes(mid, st_label, pkcs1_tbs, component_info)
        if modified_pkcs1_tbs == None and modified_component_info == None:
            mid_res = False
        else:    
            p, c = None, None
            if before_inject:
                p, c = inject_before(rand_str*mid, 'hidden_byte_' + str(mid), comp, modified_pkcs1_tbs, modified_component_info)
            else:
                p, c = inject(rand_str*mid, 'hidden_byte_' + str(mid), comp, i, modified_pkcs1_tbs, modified_component_info, tlv_adjustment)
            mid_res = bug_detector(p, c, target_path, args)
        if not mid_res:
            if mid == low:
                # cannot hide <low> number of bytes
                return -1
            else:
                high = mid - 1
        else:   # we can hide possibly larger than <mid> number of bytes


            if mid == high:
                # we can hide <high> number of bytes
                break
            else:
                modified_pkcs1_tbs, modified_component_info = steal_bytes(mid + 1, st_label, pkcs1_tbs, component_info)
                mid1_res = False
                if modified_pkcs1_tbs == None and modified_component_info == None:
                    mid_res = False
                else:    
                    if before_inject:
                        p, c = inject_before(rand_str*(mid + 1), 'hidden_byte_' + str(mid), comp, modified_pkcs1_tbs, modified_component_info)
                    else:
                        p, c = inject(rand_str*(mid + 1), 'hidden_byte_' + str(mid), comp, i, modified_pkcs1_tbs, modified_component_info, tlv_adjustment)
                    mid1_res = bug_detector(p, c, target_path, args)
                    
                if mid1_res:
                    low = mid + 1
                else: # <mid> number of bytes is the highest we can hide
                    break
    return mid

def main():
    global MAX_NUM_BYTES_HIDING
    global MIN_NUM_BYTES_HIDING
    global PORT #numan947

    if len(sys.argv) != 4:
        print('usage: python3 {} <target_binary> <exp/imp> <port>'.format(sys.argv[0]))
        exit(1)
    
    if not os.path.exists(sys.argv[1]):
        print('Target binary cannot be found at "{}"'.format(sys.argv[1]))
        print('You should specify fully qualified file name of the target binary.')
        exit(1)
    
    if sys.argv[2].lower() != 'exp' and sys.argv[2].lower() != 'imp':
        print('Input structure type for this fuzz test should be "exp" or "imp" for explicit or implicit cases, resp.')
        exit(1)

    args = [str(N_len)] + [hM] + [TARGET_HASH_ID[1]]

    components = None
    exp = sys.argv[2].lower() == 'exp'
    if exp:
        components = ('leading_byte', 'block_type', 'padding_bytes', 'padding_end', 'asb@type', 'asb@length', 'hash_algo@type', 'hash_algo@length', 'hash_id@type', 'hash_id@length', 'hash_id@value', 'param@type', 'param@length', 'param@value', 'hash_value@type', 'hash_value@length', 'hash_value@value')
    else:
        components = ('leading_byte', 'block_type', 'padding_bytes', 'padding_end', 'asb@type', 'asb@length', 'hash_algo@type', 'hash_algo@length', 'hash_id@type', 'hash_id@length', 'hash_id@value', 'hash_value@type', 'hash_value@length', 'hash_value@value')
    
    pkcs1_tbs, component_info = generate_pkcs1_structure(hM, TARGET_HASH_ID[0], exp, N_len)
    
    initial_sanity_check(pkcs1_tbs, sys.argv[1], args)
    
    start_dt = datetime.now()
    
    PORT = int(sys.argv[3]) # numan947

    print('Fuzzing started at {}'.format(start_dt))

    signal.signal(signal.SIGINT, partial(signal_handler, start_dt))
    signal.signal(signal.SIGTSTP, partial(signal_handler, start_dt))

    print('It will take long time; please be patient. You can do Ctrl-z to exit the fuzzer whenever you want.\n')
    
    for st_label in STEAL_SET:
        print('(-) Stealing from {} component.'.format(st_label))
        hide_set = COMPONENTS_SET.difference({st_label})
        num_bytes = MIN_NUM_BYTES_HIDING
        modified_pkcs1_tbs, modified_component_info = steal_bytes(num_bytes, st_label, pkcs1_tbs, component_info)
        if modified_pkcs1_tbs == None and modified_component_info == None:
            continue

        for comp in components:
            if comp in hide_set and '@length' not in comp:
                if components.index(comp) == 0 or components.index(comp) == components.index(st_label) + 1:
                    for r in range(len(VOI)):
                        before_inject_pkcs1_tbs, before_inject_component_info = inject_before(dec_to_hex(VOI[r])*num_bytes, 'hidden_byte_' + str(num_bytes), comp, modified_pkcs1_tbs, modified_component_info)
                        
                        if bug_detector(before_inject_pkcs1_tbs, before_inject_component_info, sys.argv[1], args):
                            bin_res = binary_search(num_bytes + 1, MAX_NUM_BYTES_HIDING, pkcs1_tbs, component_info, st_label, comp, 0, dec_to_hex(VOI[r]), sys.argv[1], args, True)
                            if bin_res == -1:
                                print('%'*36)
                                print('+ Vulnerable component = {}'.format(comp))
                                print('+ Max number of injected byte = 1')
                                print('%'*36 + '\n\n\n')
                            else:
                                print('%'*36)
                                print('+ Vulnerable component = {}'.format(comp))
                                print('+ Max number of injected byte = {}'.format(bin_res))
                                print('%'*36 + '\n\n\n')

                
                target_range = range(modified_component_info[comp]['length'] + 1) if '@value' in comp else range(1, modified_component_info[comp]['length'] + 1)
                for i in target_range:
                    for r in range(len(VOI)):
                        injected_pkcs1_tbs, injected_component_info = inject(dec_to_hex(VOI[r])*num_bytes, 'hidden_byte_' + str(num_bytes), comp, i, modified_pkcs1_tbs, modified_component_info)
                        
                        if bug_detector(injected_pkcs1_tbs, injected_component_info, sys.argv[1], args):
                            bin_res = binary_search(num_bytes + 1, MAX_NUM_BYTES_HIDING, pkcs1_tbs, component_info, st_label, comp, i, dec_to_hex(VOI[r]), sys.argv[1], args)
                            if bin_res == -1:
                                print('%'*36)
                                print('+ Vulnerable component = {}'.format(comp))
                                print('+ Max number of injected byte = 1')
                                print('%'*36)
                            else:
                                print('%'*36)
                                print('+ Vulnerable component = {}'.format(comp))
                                print('+ Max number of injected byte = {}'.format(bin_res))
                                print('%'*36 + '\n\n\n')
                if comp == 'hash_value@value':
                    for r in range(len(VOI)):
                        injected_pkcs1_tbs, injected_component_info = inject(dec_to_hex(VOI[r])*num_bytes, 'hidden_byte_' + str(num_bytes), comp, modified_component_info[comp]['length'], modified_pkcs1_tbs, modified_component_info, False)
                        if bug_detector(injected_pkcs1_tbs, injected_component_info, sys.argv[1], args):
                            bin_res = binary_search(num_bytes + 1, MAX_NUM_BYTES_HIDING, pkcs1_tbs, component_info, st_label, comp, modified_component_info[comp]['length'], dec_to_hex(VOI[r]), sys.argv[1], args, tlv_adjustment=False)
                            if bin_res == -1:
                                print('%'*36)
                                print('+ Vulnerable component = {} tailing'.format(comp))
                                print('+ Max number of injected byte = 1')
                                print('%'*36)
                            else:
                                print('%'*36)
                                print('+ Vulnerable component = {} tailing'.format(comp))
                                print('+ Max number of injected byte = {}'.format(bin_res))
                                print('%'*36 + '\n\n\n') 
    now_dt = datetime.now()
    elapsed_dt = now_dt - start_dt
    print('Finished at {}'.format(now_dt))
    print('Elapsed time: {}'.format(elapsed_dt))
    

if __name__ == "__main__":
    main()
    


