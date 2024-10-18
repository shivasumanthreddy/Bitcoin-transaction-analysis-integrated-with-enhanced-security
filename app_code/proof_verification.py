import os
import sys
import random
import time
import psutil

DEBUG = True  # Set this to False to disable debug mode


def read_transaction(file_path):
    """Read the transaction data from the specified file."""
    with open(file_path, 'rb') as file:
        return file.read()

def generate_deletion_indices(original_length, modified_length):
    """Generate random deletion indices."""
    return random.sample(range(original_length), original_length - modified_length)

def write_deleted_indices(indices, file_path):
    """Write the deletion indices to the specified file."""
    with open(file_path, 'w') as file:
        file.write(','.join(map(str, indices)))

def replace_characters(original, deletion_indices):
    """Replace characters at deletion indices with zero."""
    modified = bytearray(original)  # Convert to mutable bytearray
    for index in deletion_indices:
        modified[index] = ord('0')  # Replace with '0' (byte)
    return bytes(modified)

def calculate_delay(file_path):
    """Calculate the delay based on the file size."""
    file_size = os.path.getsize(file_path)  # Get the file size in bytes
    return random.uniform(5, 10) + file_size / 100000

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
        print("Memory consumption for verifying modified transaction: {:.2f} MB".format(process.memory_info().rss / (1024 * 1024)))


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
