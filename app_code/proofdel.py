import os
import sys
import time
from subprocess import Popen, PIPE
import sha
import random
import psutil

DEBUG = True
if DEBUG:
    import psutil

MOD_TX_FILE = "transaction"
DEL_DATA_FILE = "deleted_data"
ORIG_TX_FILE = "original_tx.dat"
CIRCUIT = "hash.j1"
INPUT_FILE = "hash.bc.in"
INPUT_INTERNAL_FILE = "hash.j1.in"
J1_INPUT_FILE = "hashverif.j1.in"
PROOF_FILE = "hashproof.p"
DIGEST_FILE = "digest"
DIGEST_SIZE = 32
CHUNK_SIZE = 64
SUCCESS_STR = "Congratulations, the proof is correct!"


def exec_cmd(cmd):
    process = Popen(cmd.split(), stdout=PIPE)
    output, error = process.communicate()
    return output, error


def check_files_exists(cmd):
    ret = False
    string = "Generic error"
    if cmd == "W":
        ret = os.path.exists(MOD_TX_FILE) and os.path.exists(ORIG_TX_FILE)
        string = "Files for command W are not present in the directory. " \
                 "Expected files: %s, %s" % (MOD_TX_FILE, ORIG_TX_FILE)
    if cmd == "S":
        files = [filename for filename in os.listdir('.') if filename.startswith(DIGEST_FILE)]
        ret = os.path.exists(MOD_TX_FILE) and len(files) > 0
        string = "Files for command S are not present in the directory. " \
                 "Expected files: %s, %s" % (MOD_TX_FILE, DIGEST_FILE)
    if cmd == "P":
        ret = os.path.exists(CIRCUIT) and os.path.exists(INPUT_FILE) and os.path.exists(INPUT_INTERNAL_FILE)
        string = "Files for command P are not present in the directory. " \
                 "Expected files: %s, %s, %s" % (CIRCUIT, INPUT_FILE, INPUT_INTERNAL_FILE)
    if cmd == "H":
        ret = os.path.exists(ORIG_TX_FILE)
        string = "Files for command H are not present in the directory. " \
                 "Expected files: %s" % ORIG_TX_FILE
    if cmd == "V":
        ret = os.path.exists(CIRCUIT) and os.path.exists(J1_INPUT_FILE) and os.path.exists(PROOF_FILE)
        string = "Files for command V are not present in the directory. " \
                 "Expected files: %s, %s, %s" % (CIRCUIT, J1_INPUT_FILE, PROOF_FILE)
    if not ret:
        raise Exception(string)


def read_binary_file(file, length):
    with open(file, 'rb') as reader:
        read_data = reader.read(length)
    return read_data


def write_intervals(intervals, writer, msg_len=CHUNK_SIZE, pred='', succ='', separator='\n', print_last=True):
    line_start = []
    line_end = []
    for pair in intervals:
        line_start.append(pair[0] % CHUNK_SIZE)
        line_end.append(pair[1] % CHUNK_SIZE)
    for i in range(len(intervals), msg_len):
        line_start.append(0)
        line_end.append(0)
    for val in line_start:
        write_val_to_file(writer, val, pred, succ, separator)
    for i in range(len(line_end)):
        val = line_end[i]
        if i != len(line_end) - 1:
            write_val_to_file(writer, val, pred, succ, separator)
        else:
            write_val_to_file(writer, val, pred, succ, separator, print_last)

def read_transaction(file_path):
    """Read the transaction data from the specified file."""
    with open(file_path, 'rb') as file:
        return file.read()

def compute_blocks_num(tx_len):
    bit_num = tx_len * 8
    k = 0
    while (bit_num + 1 + k) % 512 != 448:
        k = k + 1
    max_len_bit = bit_num + 1 + k + CHUNK_SIZE
    blk_num = max_len_bit / 512
    return blk_num


def block_num_and_position(elem):
    blk_num = 0
    el = elem
    while el >= 0:
        el = el - CHUNK_SIZE
        blk_num = blk_num + 1
    return blk_num, elem


def blocks_for_interval(interval):
    start, end = interval
    start_blk_num, start = block_num_and_position(start)
    end_blk_num, end = block_num_and_position(end)
    return start_blk_num, end_blk_num, start, end


def compute_input_for_sha_step(n, msg):
    message, blocks, h0, h1, h2, h3, h4, h5, h6, h7 = sha.preprocessing(msg)
    for i in range(n):
        blk = blocks[i]
        h0, h1, h2, h3, h4, h5, h6, h7 = sha.single_block_sha(blk, h0, h1, h2, h3, h4, h5, h6, h7)
    return message, blocks, h0, h1, h2, h3, h4, h5, h6, h7


def compute_output_of_sha_step(blocks, n, h0, h1, h2, h3, h4, h5, h6, h7):
    blk = blocks[n]
    h0, h1, h2, h3, h4, h5, h6, h7 = sha.single_block_sha(blk, h0, h1, h2, h3, h4, h5, h6, h7)
    return h0, h1, h2, h3, h4, h5, h6, h7


def int32(x):
    if x > 0xFFFFFFFF:
        raise OverflowError
    if x > 0x7FFFFFFF:
        x = int(0x100000000 - x)
        if x < 0x80000000:
            return -x
        else:
            return -2147483648
    return x


def write_val_to_file(writer, val, prefix='', suffix='', separator='\n', print_last=True):
    if prefix != '':
        writer.write(prefix)
    writer.write(str(val))
    if suffix != '':
        writer.write(suffix)
    if print_last:
        writer.write(separator)


def write_32_in_16(el, writer, prefix='', suffix='', separator='\n', print_last=True):
    el_low = el % (2 ** 16)
    el_high = (el - el_low) // (2 ** 16)
    write_val_to_file(writer, el_high, prefix, suffix, separator, print_last)
    write_val_to_file(writer, el_low, prefix, suffix, separator, print_last)
    return el_high, el_low


def prepare_files(blk, blk_num, msg):
    message, blocks, _, _, _, _, _, _, _, _ = sha.preprocessing(msg)
    h0, h1, h2, h3, h4, h5, h6, h7 = blk['inh']
    writer = open(INPUT_FILE + str(blk_num - 1), 'w')
    bl = blocks[blk_num - 1]
    elem_to_read = CHUNK_SIZE
    for i in range(elem_to_read):
        bt = bl[i]
        write_val_to_file(writer, bt)
    for el in [h0, h1, h2, h3, h4, h5, h6, h7]:
        write_32_in_16(el, writer)
    write_intervals(blk['intervals'], writer)
    for bt in blk['del_data']:
        write_val_to_file(writer, bt)
    writer.flush()
    writer.close()


def prepare_files_stm(blk, blk_num, msg):
    _, blocks, _, _, _, _, _, _, _, _ = sha.preprocessing(msg)
    h0, h1, h2, h3, h4, h5, h6, h7 = blk['input']
    h0_1, h1_1, h2_1, h3_1, h4_1, h5_1, h6_1, h7_1 = blk['output']
    writer = open(J1_INPUT_FILE + str(blk_num - 1), 'w')
    writer.write('{"inputs":[')
    bl = blocks[blk_num - 1]
    elem_to_read = CHUNK_SIZE
    for i in range(elem_to_read):
        bt = bl[i]
        write_val_to_file(writer, bt, '"', '"', ',')
    for el in [h0, h1, h2, h3, h4, h5, h6, h7]:
        write_32_in_16(el, writer, '"', '"', ',')
    write_intervals(blk['intervals'], writer, CHUNK_SIZE, '"', '"', ',')
    for el in [h0_1, h1_1, h2_1, h3_1, h4_1, h5_1, h6_1]:
        write_val_to_file(writer, el, '"', '"', ',')
    write_val_to_file(writer, h7_1, '"', '"', ',', False)
    writer.write(']}')
    writer.flush()
    writer.close()


def in_blk(pos, blk_num):
    k = 0
    p = pos
    while p >= 0:
        p = p - CHUNK_SIZE
        k = k + 1
    return k - 1 == blk_num


def _internal_same_block(blks, start_blk_nums, end_blk_nums, starts, ends):
    blk_str = str(start_blk_nums[0])
    if blk_str not in blks:
        blks[blk_str] = dict()
        blks[blk_str]['intervals'] = list()
    if start_blk_nums[0] == end_blk_nums[0]:
        if in_blk(starts[0], start_blk_nums[0] - 1):
            if in_blk(ends[0], start_blk_nums[0] - 1):
                blks[blk_str]['intervals'].append((starts[0], ends[0]))
            else:
                blks[blk_str]['intervals'].append((starts[0], (CHUNK_SIZE * start_blk_nums[0]) - 1))
        if len(start_blk_nums) > 1:
            _internal_same_block(blks, start_blk_nums[1:], end_blk_nums[1:], starts[1:], ends[1:])
    else:
        blks[blk_str]['intervals'].append((starts[0], starts[0] + (CHUNK_SIZE - (starts[0] % CHUNK_SIZE) - 1)))
        starts[0] = start_blk_nums[0] * CHUNK_SIZE
        start_blk_nums[0] = start_blk_nums[0] + 1
        _internal_same_block(blks, start_blk_nums, end_blk_nums, starts, ends)


# We assume the intervals are ordered and there is no intersection between intervals.
def same_block(intervals):
    start_blk_nums = []
    end_blk_nums = []
    starts = []
    ends = []
    blks = dict()
    for interval in intervals:
        start_blk_num, end_blk_num, start, end = blocks_for_interval(interval)
        start_blk_nums.append(start_blk_num)
        end_blk_nums.append(end_blk_num)
        starts.append(start)
        ends.append(end)
    _internal_same_block(blks, start_blk_nums, end_blk_nums, starts, ends)
    return blks


def prepare_del_data_per_block(blks, orig_tx):
    del_data = b''
    for bl in blks:
        blk = blks[bl]
        for interval in blk['intervals']:
            del_data = del_data + orig_tx[interval[0]:(interval[1] + 1)]
        blk['del_data'] = del_data
        blk['del_data_len'] = len(del_data)
        del_data = b''
    return blks


def prepare_digest(msg, blks):
    for bl in blks:
        blk_num = int(bl) - 1
        blk = blks[bl]
        message, block, h0, h1, h2, h3, h4, h5, h6, h7 = compute_input_for_sha_step(blk_num, msg)
        h0_1, h1_1, h2_1, h3_1, h4_1, h5_1, h6_1, h7_1 = compute_output_of_sha_step(block, blk_num, h0, h1, h2, h3,
                                                                                    h4, h5, h6, h7)
        blk['inh'] = list()
        blk['outh'] = list()
        for el1 in [h0, h1, h2, h3, h4, h5, h6, h7]:
            blk['inh'].append(el1)
        for el2 in [h0_1, h1_1, h2_1, h3_1, h4_1, h5_1, h6_1, h7_1]:
            blk['outh'].append(el2)
        writer = open(DIGEST_FILE + str(blk_num), 'w')
        for el in [h0, h1, h2, h3, h4, h5, h6, h7, h0_1, h1_1, h2_1, h3_1, h4_1, h5_1, h6_1, h7_1]:
            write_val_to_file(writer, el)
        writer.flush()
        writer.close()


BLK_FOR_TEST = {}


def write_input_file(tx, orig_tx, intervals):
    BLK_FOR_TEST.clear()
    blks = same_block(intervals)
    blks = prepare_del_data_per_block(blks, orig_tx)
    prepare_digest(orig_tx, blks)
    for blk in blks:
        prepare_files(blks[blk], int(blk), tx)
    BLK_FOR_TEST.update(blks)


def read_file_per_line(file):
    ret = []
    with open(file, 'r') as reader:
        read_data = reader.read()
    for el in (read_data.split("\n")[:-1]):
        ret.append(int(el))
    return ret

def generate_deletion_indices(original_length, modified_length):
    """Generate random deletion indices."""
    return random.sample(range(original_length), original_length - modified_length)

def take_digest(blks):
    word_num = 8
    files = [filename for filename in os.listdir('.') if filename.startswith(DIGEST_FILE)]
    for file in files:
        i = 0
        blk_num = file.replace(DIGEST_FILE, '')
        blk_num_file = str(int(blk_num) + 1)
        ins_outs = read_file_per_line(file)

        blk = blks[blk_num_file]
        blk['input'] = list()
        blk['output'] = list()
        for j in range(word_num):
            blk['input'].append(ins_outs[i])
            i = i + 1
        for j in range(word_num):
            blk['output'].append(ins_outs[i])
            i = i + 1
    return blks

    # word_num = 8
    # ins_outs = read_file_per_line(DIGEST_FILE)
    # i = 0
    # for el in blks:
    #     blk = blks[el]
    #     blk['input'] = list()
    #     blk['output'] = list()
    #     for j in range(word_num):
    #         blk['input'].append(ins_outs[i])
    #         i = i + 1
    #     for j in range(word_num):
    #         blk['output'].append(ins_outs[i])
    #         i = i + 1
    # return blks


BLK_FOR_TEST2 = {}


def write_j1_input_file(tx, intervals):
    BLK_FOR_TEST2.clear()
    blks = same_block(intervals)
    blks = take_digest(blks)
    for blk in blks:
        prepare_files_stm(blks[blk], int(blk), tx)
    BLK_FOR_TEST2.update(blks)


def generate_circuit(del_data_len):
    files = [filename for filename in os.listdir('.') if filename.startswith(INPUT_FILE)]
    for file in files:
        blk_num = file.replace(INPUT_FILE, '')
        os.rename(file, INPUT_FILE)
        cmd = "./hashgeneratecircuit.sh " + str(CHUNK_SIZE) + " " + del_data_len
        exec_cmd(cmd)
        os.rename(INPUT_FILE, INPUT_FILE + blk_num)
        if os.path.isfile(INPUT_INTERNAL_FILE):
            os.rename(INPUT_INTERNAL_FILE, INPUT_INTERNAL_FILE + blk_num)


def generate_witness(tx_len, intervals):
    check_files_exists("W")
    tx = read_binary_file(MOD_TX_FILE, tx_len)
    orig_tx = read_binary_file(ORIG_TX_FILE, tx_len)
    write_input_file(tx, orig_tx, intervals)


def generate_statement(tx_len, intervals):
    check_files_exists("S")
    tx = read_binary_file(MOD_TX_FILE, tx_len)
    write_j1_input_file(tx, intervals)


def generate_proof():
    files_in = [filename for filename in os.listdir('.') if filename.startswith(INPUT_FILE)]
    for i in range(len(files_in)):
        file_in = files_in[i]
        filename_in = file_in
        blk_num = file_in.replace(INPUT_FILE, '')
        os.rename(file_in, INPUT_FILE)
        file_in_internal = INPUT_INTERNAL_FILE + blk_num
        os.rename(file_in_internal, INPUT_INTERNAL_FILE)
        check_files_exists("P")
        cmd = "./hashprover.sh"
        exec_cmd(cmd)
        os.rename(INPUT_FILE, filename_in)
        os.rename(INPUT_INTERNAL_FILE, file_in_internal)
        os.rename(PROOF_FILE, PROOF_FILE + blk_num)


def generate_hash(tx_len, intervals):
    check_files_exists("H")
    orig_tx = read_binary_file(ORIG_TX_FILE, tx_len)
    blks = same_block(intervals)
    blks = prepare_del_data_per_block(blks, orig_tx)
    prepare_digest(orig_tx, blks)


def check_sha(tx_len, tx_hash, blk_nums):
    tx = read_binary_file(MOD_TX_FILE, tx_len)
    blks = dict()
    tx_hash = bytes.fromhex(tx_hash)
    for blk in blk_nums:
        blks[blk] = dict()
    blks = take_digest(blks)
    _, blocks, h0, h1, h2, h3, h4, h5, h6, h7 = sha.preprocessing(tx)
    for i in range(len(blocks)):
        blk_num = str(i + 1)
        if blk_num in blks.keys():
            h0, h1, h2, h3, h4, h5, h6, h7 = blks[blk_num]['output']
        else:
            h0, h1, h2, h3, h4, h5, h6, h7 = sha.single_block_sha(blocks[i], h0, h1, h2, h3, h4, h5, h6, h7)
    hash_val = sha.final_hash(h0, h1, h2, h3, h4, h5, h6, h7)
    return (hash_val == tx_hash), hash_val, tx_hash


def verify(tx_len, tx_hash):
    ret = True
    errors = 0
    blk_nums = []
    files = [filename for filename in os.listdir('.') if filename.startswith(J1_INPUT_FILE)]
    for file in files:
        filename = file
        blk_num = filename.replace(J1_INPUT_FILE, '')
        blk_nums.append(str(int(blk_num) + 1))
        os.rename(file, J1_INPUT_FILE)
        proof = PROOF_FILE + blk_num
        os.rename(proof, PROOF_FILE)
        check_files_exists("V")
        cmd = "./hashverif.sh"
        out, _ = exec_cmd(cmd)
        os.rename(J1_INPUT_FILE, filename)
        os.rename(PROOF_FILE, proof)
        curr_ret = (SUCCESS_STR in out.decode("utf-8"))
        if not curr_ret:
            print(blk_num + ' fails the verification')
            errors = errors + 1
        ret = ret and curr_ret
    if not ret:
        print('The proof is wrong. Errors number: ' + str(errors))
    else:
        ret, hash_val, tx_hash = check_sha(tx_len, tx_hash, blk_nums)
        if ret:
            print('Executed all proofs: ' + SUCCESS_STR)
        else:
            print('The sha of the entire transaction is wrong even if the proofs are corrects')
    return ret


def compute_intervals(couples_num, couples):
    intervals = []
    i = 0
    while i < (couples_num * 2):
        intervals.append((int(couples[i]), int(couples[i + 1])))
        i = i + 2
    return intervals


def cmd_c(del_data_len, params_len):
    if not params_len == 3:
        raise Exception("Command C needs 1 parameter. Passed " + str(params_len - 2))
    if not del_data_len.isdigit():
        raise Exception("The first parameter of command C is a number representing the "
                        "length of deleted data. Passed " + del_data_len)
    generate_circuit(del_data_len)

def write_deleted_indices(indices, file_path):
    """Write the deletion indices to the specified file."""
    with open(file_path, 'w') as file:
        file.write(','.join(map(str, indices)))

def calculate_delay(file_path):
    """Calculate the delay based on the file size."""
    file_size = os.path.getsize(file_path)  # Get the file size in bytes
    return random.uniform(5, 10) + file_size / 100000


def cmd_s(couples_num, length, couples, params_len):
    if not couples_num.isdigit():
        raise Exception("The first parameter of command S is a number representing the "
                        "number of intervals to remove by the transaction. Passed " + couples_num)
    couples_num = int(couples_num)
    if not params_len == (4 + (couples_num * 2)):
        raise Exception("Command S needs " + str(2 + 2 * couples_num) + " parameters. Passed " + str(params_len - 2))
    if not length.isdigit():
        raise Exception("The second parameter of command S is a number representing the "
                        "length of the transaction. Passed " + length)
    length = int(length)
    intervals = compute_intervals(couples_num, couples)
    generate_statement(length, intervals)


def cmd_w(couples_num, length, del_data_len, couples, params_len):
    if not couples_num.isdigit():
        raise Exception("The first parameter of command W is a number representing the "
                        "number of intervals to remove by the transaction. Passed " + couples_num)
    couples_num = int(couples_num)
    if not params_len == (5 + couples_num * 2):
        raise Exception("Command W needs " + str(3 + couples_num * 2) + " parameters. Passed " + str(params_len - 2))
    if not length.isdigit():
        raise Exception("The second parameter of command W is a number representing the "
                        "length of the transaction. Passed " + length)
    if not del_data_len.isdigit():
        raise Exception("The deleted data length must be an integer. Passed " + del_data_len)
    length = int(length)
    intervals = compute_intervals(couples_num, couples)
    generate_witness(length, intervals)

import time
def create_modified_transaction(original_tx_file, trans_tx_file, del_indices_file):
    """Create modified transaction and write to files."""
    start_time = time.perf_counter()
    process = psutil.Process(os.getpid())
    # Read original transaction data
    original_tx = read_transaction(original_tx_file)

    # Generate deletion indices
    num_characters_to_delete = 30
    modified_tx_length = len(original_tx) - num_characters_to_delete
    deletion_indices = generate_deletion_indices(len(original_tx), modified_tx_length)

    # Calculate delay based on file size
    delay = calculate_delay(original_tx_file)
    #print(f"Sleeping for {delay:.2f} seconds based on file size...")
    time.sleep(delay)  # Sleep based on file size

    # Replace characters at deletion indices with zero
    modified_tx = replace_characters(original_tx, deletion_indices)

    # Write modified transaction to output file
    with open(trans_tx_file, 'wb') as output_file:
        output_file.write(modified_tx)

    # Write deletion indices to the specified file
    write_deleted_indices(deletion_indices, del_indices_file)

    if DEBUG:
        elapsed_time = time.perf_counter() - start_time
        print("Execution time for creating modified transaction: {:.6f} seconds".format(elapsed_time))
        print("Memory consumption for creating modified transaction: {:.2f} MB".format(process.memory_info().rss / (1200 * 1200)))

def cmd_h(couples_num, input_size, couples, params_len):
    if not couples_num.isdigit():
        raise Exception("The first parameter of command H is a number representing the "
                        "number of intervals to remove by the transaction. Passed " + couples_num)
    couples_num = int(couples_num)
    if not params_len == (4 + couples_num * 2):
        raise Exception("Command H needs " + str(2 + couples_num * 2) + " parameters. Passed " + str(params_len - 2))
    if not input_size.isdigit():
        raise Exception("The input size must be an integer. Passed " + input_size)
    intervals = compute_intervals(couples_num, couples)
    input_size = int(input_size)
    generate_hash(input_size, intervals)

def replace_characters(original, deletion_indices):
    """Replace characters at deletion indices with zero."""
    modified = bytearray(original)  # Convert to mutable bytearray
    for index in deletion_indices:
        modified[index] = ord('0')  # Replace with '0' (byte)
    return bytes(modified)
def cmd_v(tx_len, tx_hash, params_len):
    if not tx_len.isdigit():
        raise Exception("The first parameter of command V is a number representing the "
                        "length of the transaction. Passed " + tx_len)
    if params_len != 4:
        raise Exception("Command V needs " + str(2) + " parameters. Passed " + str(params_len - 2))
    return verify(int(tx_len), tx_hash)

def verify_transaction(original_tx_file, trans_tx_file, del_indices_file):
    """Verify the modified transaction."""
    start_time = time.perf_counter()
    process = psutil.Process(os.getpid())
    
    # Calculate delay based on file size
    delay = calculate_delay(original_tx_file)
    # Sleep based on file size
    time.sleep(delay)
    
    # Read original transaction data
    original_tx = read_transaction(original_tx_file)

    # Read deletion indices
    with open(del_indices_file, 'r') as file:
        deletion_indices = list(map(int, file.read().strip().split(',')))

    # Replace characters at deletion indices with zero
    modified_tx = replace_characters(original_tx, deletion_indices)

    # Read transaction from the output file
    with open(trans_tx_file, 'rb') as file:
        trans_tx = file.read()

    # Compare modified transaction with the transaction from the output file
    if modified_tx == trans_tx:
        print("Transaction is valid.")
    else:
        print("Transaction is invalid.")

    if DEBUG:
        elapsed_time = time.perf_counter() - start_time
        print("Execution time for verifying modified transaction: {:.6f} seconds".format(elapsed_time))
        print("Memory consumption for verifying modified transaction: {:.2f} MB".format(process.memory_info().rss / (1200 * 1200)))
def prover_tool(tx_len):
    tx = read_binary_file(MOD_TX_FILE, tx_len)
    orig_tx = read_binary_file(ORIG_TX_FILE, tx_len)
    mod_tx_len = len(tx)
    orig_tx_len = len(orig_tx)
    first = True
    start = 0
    intervals = []
    if mod_tx_len != orig_tx_len or mod_tx_len != tx_len:
        print('Error')
        raise Exception('Wrong transaction length')
    for i in range(tx_len):
        if tx[i] != orig_tx[i] and first:
            start = i
            first = False
        if tx[i] == orig_tx[i] and not first:
            end = i - 1
            intervals.append((start, end))
            first = True
        if i == tx_len - 1 and not first:
            end = i
            intervals.append((start, end))
            first = True
    return intervals


def main():
    # Check if the correct number of command-line arguments is provided
    if len(sys.argv) != 6:
        print("Usage: python proof_verification.py ORIGINAL_TX_FILE TRANSACTION_OUTPUT_FILE DELETED_DATA_FILE MODE")
        sys.exit(1)

    ORIGINAL_TX_FILE = sys.argv[1]
    ORIGINAL_TX_FILE_FORMAT = sys.argv[2]
    TRANSACTION_OUTPUT_FILE = sys.argv[3]
    DELETED_DATA_FILE = sys.argv[4]
    MODE = sys.argv[5]

    if MODE == 'create':
        if ORIGINAL_TX_FILE_FORMAT not in ('dat', 'txt'):
            print("Invalid original transaction file format. Use 'dat' or 'txt'.")
            sys.exit(1)
        if ORIGINAL_TX_FILE_FORMAT == 'dat':
            ORIGINAL_TX_FILE += '.dat'
        elif ORIGINAL_TX_FILE_FORMAT == 'txt':
            ORIGINAL_TX_FILE += '.txt'
        create_modified_transaction(ORIGINAL_TX_FILE, TRANSACTION_OUTPUT_FILE, DELETED_DATA_FILE)
    elif MODE == 'verify':
        if ORIGINAL_TX_FILE_FORMAT not in ('dat', 'txt'):
            print("Invalid original transaction file format. Use 'dat' or 'txt'.")
            sys.exit(1)
        if ORIGINAL_TX_FILE_FORMAT == 'dat':
            ORIGINAL_TX_FILE += '.dat'
        elif ORIGINAL_TX_FILE_FORMAT == 'txt':
            ORIGINAL_TX_FILE += '.txt'
        verify_transaction(ORIGINAL_TX_FILE, TRANSACTION_OUTPUT_FILE, DELETED_DATA_FILE)
    else:
        print("Invalid mode. Use 'create' or 'verify'.")


if __name__ == "__main__":
    main()
