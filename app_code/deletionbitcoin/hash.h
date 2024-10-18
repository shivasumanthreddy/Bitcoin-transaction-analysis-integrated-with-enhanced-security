#define  DIGEST_SIZE 32
#define  SAFE_BOUND 0
#ifndef TRANSACTION_LENGTH
#define TRANSACTION_LENGTH 32 // the byte length of the transaction - PASSED AS INPUT TO THE PREPROCESSOR
#endif
#ifndef DELETED_DATA_LENGTH
#define DELETED_DATA_LENGTH 8 // it is the length (in bytes) of the data after OP_RETURN that have been deleted - PASSED AS INPUT TO THE PREPROCESSOR
#endif
struct Input {
 unsigned   char trans[TRANSACTION_LENGTH+SAFE_BOUND]; // the public string representing the max length of the transaction. In the input file the substring of trans for the DELETED_DATA_LENGTH bytes after OP_RETURN can be arbitrary.
unsigned int start[TRANSACTION_LENGTH]; // the start index (starting from byte 0) of the deleted substring
unsigned int end[TRANSACTION_LENGTH]; // the end index (starting from byte 0) of the deleted substring
unsigned int input_size;
};
struct NzikInput{
unsigned char deleted_data[DELETED_DATA_LENGTH];
};

struct Output {
    unsigned char digest[DIGEST_SIZE+1];
};
