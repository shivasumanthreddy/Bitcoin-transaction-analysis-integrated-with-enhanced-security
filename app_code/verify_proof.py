import os
import sys
import subprocess
import json
PROOFDIR_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "files_for_proof"))
PROOFJSON_PATH = os.path.abspath(os.path.join(PROOFDIR_PATH, "proofs.json"))
PROOF_DEL_PATH  = os.path.abspath(os.path.join(PROOFDIR_PATH, "../deletionbitcoin/proofdeletions"))
VALIDATED_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "files_for_proof", "validated_transactions.json"))
SUCCESS_STR = "Congratulations, the proof is correct!"

##
# Execute the command in input and retun the content of the stdout and the stderr
def exec_cmd(cmd):
    process = subprocess.Popen(cmd.split(),stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output, error

##
# Execute the proofdeletions program with parameters H and S to setup the environment for
# the verification process.
def init_proof_env(length, couples, del_data_len, tx_size, path):
    os.chdir(path)
    cmd = " ".join([PROOF_DEL_PATH, "H", length, couples, del_data_len, tx_size])
    out1, err1 = exec_cmd(cmd)
    cmd = " ".join([PROOF_DEL_PATH, "S", length, couples, tx_size])
    out2, err2 = exec_cmd(cmd)

##
# Execute the verification command running the proofdeletions program with parameter V
def veryfy_proof():
    cmd = " ".join([PROOF_DEL_PATH, "V"])
    out, err = exec_cmd(cmd)
    return out, err

##
# Given the txid, reads the json file PROOFJSON_PATH to obtain the data related to this transaction.
# The requested data are:
# length: the maximum length of the transaction,
# couples: a string composed of length couples of numbers,
# del_data_len: the length of the string removed by the transaction,
# tx_size: the length of the current transaction,
# path: the path to the folder containing all data related to the proof of the following transaction
def prepare_cmd_line_params(txid):
    data = dict()
    with open(PROOFJSON_PATH) as json_file:
        data = json.load(json_file)
    params = data[txid]
    return params['length'], params['couples'], params['del_data_len'], params['tx_size'], params['path']

##
# Check if the output of the verification of the proof contains SUCCESS_STR
def check_output(out):
    str_out = out.decode("utf-8")
    return SUCCESS_STR in str_out

##
# Check if the current txid is the txid stored in PROOFJSON_PATH or is he value of the new hash of the
# transaction after the modification and return the txid stored in PROOFJSON_PATH of this transaction
def return_tx(txid, data):
    for key in data:
        if key == txid:
            return txid
        elif data[key]['new_hash'] == txid:
            return key
    return ''


def is_tx_in_dict(txid, data):
    ret = return_tx(txid, data)
    return not ret == ''


def check_proof(txid, data):
    length, couples, del_data_len, tx_size, path = prepare_cmd_line_params(return_tx(txid, data))
    init_proof_env(length, couples, del_data_len, tx_size, path)
    out, err = veryfy_proof()
    return check_output(out)

##
# Generate a json file containing data for all modified transaction. The data stored for each txid are:
# valid:    True/False the result of the verification procedur on the transaction,
# new_hash: an hexadecimal value that is the hash of the modified transaction,
# old_hash: an hexadecimal value that is the hash of the original transaction.
# The file is stored in VALIDATED_FILE
def update_file(txid, data, ok):
    json_str = {'valid':ok, 'new_hash':data[txid]['new_hash'], 'old_hash':data[txid]['old_hash']}
    json_str_new = {txid: json_str}
    json_cont = ''
    if os.path.exists(VALIDATED_FILE):
        with open(VALIDATED_FILE, "r")as json_file:
            json_cont = json.load(json_file)
        json_cont[txid] = json_str
    else:
        json_cont = json_str_new
    with open(VALIDATED_FILE, "w")as json_file:
        json.dump(json_cont, json_file)


def main(txid, store_data=False):
    os.chdir(PROOFDIR_PATH)
    data = ''
    with open(PROOFJSON_PATH) as json_file:
        data = json.load(json_file)
    tx_in_dict = is_tx_in_dict(txid, data)
    if not tx_in_dict:
        print("txid does not exist")
        return 1
    if check_proof(txid, data):
        if store_data:
            update_file(txid, data, ok=True)
        print("the proof is correct")
        return 0
    else:
        if store_data:
            update_file(txid, data, ok=False)
        print("the proof is wrong")
        return 1

def main2():
    with open(PROOFJSON_PATH) as json_file:
        data = json.load(json_file)
    for txid in data:
        main(txid, True)



if __name__ == "__main__":
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        main2()