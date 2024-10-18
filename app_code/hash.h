#define  DIGEST_SIZE 32
#define  SAFE_BOUND 0
#define TRANSACTION_LENGTH 64 // the byte length of the transaction - PASSED AS INPUT TO THE PREPROCESSOR
#define DELETED_DATA_LENGTH 64 // it is the length (in bytes) of the data after OP_RETURN that have been deleted - PASSED AS INPUT TO THE PREPROCESSOR
#define INPUT_NUM_FOR_CHUNK_SHA 8
#define INPUT_16B_FOR_CHUNK_SHA 2



struct Input {
 unsigned char trans[TRANSACTION_LENGTH]; 
 unsigned int h_in0[INPUT_16B_FOR_CHUNK_SHA];
 unsigned int h_in1[INPUT_16B_FOR_CHUNK_SHA];
 unsigned int h_in2[INPUT_16B_FOR_CHUNK_SHA];
 unsigned int h_in3[INPUT_16B_FOR_CHUNK_SHA];
 unsigned int h_in4[INPUT_16B_FOR_CHUNK_SHA];
 unsigned int h_in5[INPUT_16B_FOR_CHUNK_SHA];
 unsigned int h_in6[INPUT_16B_FOR_CHUNK_SHA];
 unsigned int h_in7[INPUT_16B_FOR_CHUNK_SHA];
 //unsigned int h_out[INPUT_NUM_FOR_CHUNK_SHA];
 unsigned int start[TRANSACTION_LENGTH]; // the start index (starting from byte 0) of the deleted substring
 unsigned int end[TRANSACTION_LENGTH]; // the end index (starting from byte 0) of the deleted substring
};
struct NzikInput{
unsigned char deleted_data[DELETED_DATA_LENGTH];
};

struct Output {
    //unsigned char h_out[DIGEST_SIZE]; 
	unsigned int h_out[INPUT_NUM_FOR_CHUNK_SHA]; 
};
