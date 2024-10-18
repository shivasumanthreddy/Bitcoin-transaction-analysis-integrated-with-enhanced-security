#include "hash.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>




//char transaction[TRANSACTION_LENGTH];
//char deleted_data[DELETED_DATA_LENGTH];
//unsigned char *transaction="ÿÿE000000000000000000000000000000000000000000000000000000000000000000000";
//unsigned char *transaction="aaE000000000000000000000000000000000000000000000000000000000000000000000";
//unsigned char *deleted_data=  "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";



#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}
#define SHA2_PACK32(str, x)                   \
{                                             \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}
#define  SHA224_256_BLOCK_SIZE  64


class SHA256
{
protected:
    typedef unsigned char uint8;
    typedef unsigned int uint32;
    typedef unsigned long long uint64;
   
    uint32 sha256_k[64];
			 
	//static const unsigned int SHA224_256_BLOCK_SIZE = (512/8);
public:
    __attribute__((always_inline)) SHA256()
    {
        sha256_k[0] = 0x428a2f98; sha256_k[1] = 0x71374491; sha256_k[2] = 0xb5c0fbcf; sha256_k[3] = 0xe9b5dba5;
        sha256_k[4] = 0x3956c25b; sha256_k[5] = 0x59f111f1; sha256_k[6] = 0x923f82a4; sha256_k[7] = 0xab1c5ed5;
        sha256_k[8] = 0xd807aa98; sha256_k[9] = 0x12835b01; sha256_k[10] = 0x243185be; sha256_k[11] = 0x550c7dc3;
        sha256_k[12] = 0x72be5d74; sha256_k[13] = 0x80deb1fe; sha256_k[14] = 0x9bdc06a7; sha256_k[15] = 0xc19bf174;
        sha256_k[16] = 0xe49b69c1; sha256_k[17] = 0xefbe4786; sha256_k[18] = 0xfc19dc6; sha256_k[19] = 0x240ca1cc;
        sha256_k[20] = 0x2de92c6f; sha256_k[21] = 0x4a7484aa; sha256_k[22] = 0x5cb0a9dc; sha256_k[23] = 0x76f988da;
        sha256_k[24] = 0x983e5152; sha256_k[25] = 0xa831c66d; sha256_k[26] = 0xb00327c8; sha256_k[27] = 0xbf597fc7;
        sha256_k[28] = 0xc6e00bf3; sha256_k[29] = 0xd5a79147; sha256_k[30] = 0x6ca6351; sha256_k[31] = 0x14292967;
        sha256_k[32] = 0x27b70a85; sha256_k[33] = 0x2e1b2138; sha256_k[34] = 0x4d2c6dfc; sha256_k[35] = 0x53380d13;
        sha256_k[36] = 0x650a7354; sha256_k[37] = 0x766a0abb; sha256_k[38] = 0x81c2c92e; sha256_k[39] = 0x92722c85;
        sha256_k[40] = 0xa2bfe8a1; sha256_k[41] = 0xa81a664b; sha256_k[42] = 0xc24b8b70; sha256_k[43] = 0xc76c51a3;
        sha256_k[44] = 0xd192e819; sha256_k[45] = 0xd6990624; sha256_k[46] = 0xf40e3585; sha256_k[47] = 0x106aa070;
        sha256_k[48] = 0x19a4c116; sha256_k[49] = 0x1e376c08; sha256_k[50] = 0x2748774c; sha256_k[51] = 0x34b0bcb5;
        sha256_k[52] = 0x391c0cb3; sha256_k[53] = 0x4ed8aa4a; sha256_k[54] = 0x5b9cca4f; sha256_k[55] = 0x682e6ff3;
        sha256_k[56] = 0x748f82ee; sha256_k[57] = 0x78a5636f; sha256_k[58] = 0x84c87814; sha256_k[59] = 0x8cc70208;
        sha256_k[60] = 0x90befffa; sha256_k[61] = 0xa4506ceb; sha256_k[62] = 0xbef9a3f7; sha256_k[63] = 0xc67178f2;

        m_h[0] = 0x6a09e667;
        m_h[1] = 0xbb67ae85;
        m_h[2] = 0x3c6ef372;
        m_h[3] = 0xa54ff53a;
        m_h[4] = 0x510e527f;
        m_h[5] = 0x9b05688c;
        m_h[6] = 0x1f83d9ab;
        m_h[7] = 0x5be0cd19;

        m_len = 0;
        m_tot_len = 0;
    }

	void update(const unsigned char *message, unsigned int len);
    void final(unsigned char *digest);
   //static const unsigned int DIGEST_SIZE = ( 32);
 
protected:
	void transform(const unsigned char *message, unsigned int block_nb);
    unsigned int m_tot_len;
    unsigned int m_len;
    unsigned char m_block[2*SHA224_256_BLOCK_SIZE];
    uint32 m_h[8];
};
 
 extern "C" {
    void outsource(Input *, NzikInput*, Output *);
//    extern void _unroll_hint(unsigned);
};

inline __attribute__((always_inline)) void SHA256::transform(const unsigned char *message, unsigned int block_nb)
{
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;
    int j;
    printf("block_nb:%d\n",block_nb);
    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);
        for (j = 0; j < 16; j++) {
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++) {
            w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++) {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++) {
	    printf("m_h[%d]=%u,wv[%d]=%u\n",j,m_h[j],j,wv[j]);
            m_h[j] += wv[j];
        }
    }
}

inline __attribute__((always_inline)) void * memcopy( unsigned char * destination, const  unsigned char * source, size_t num )
{
	for (int i = 0 ; i < num ; ++i)
	{
		*(destination+i) = *(source+i);
	}
	return destination;
}


inline __attribute__((always_inline)) void SHA256::update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    printf("m_len:%d\n",m_len);
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    printf("rem_len:%d\n",rem_len);
    memcopy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE) {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    printf("len:%d, rem_len:%d new_len: %d block_nb between the two transforms:%d\n",len,rem_len,new_len,block_nb);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    printf("rem_len2:%d\n",rem_len);
    memcopy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}
 
 inline __attribute__((always_inline)) void SHA256::final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
                     < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    //memset(m_block + m_len, 0, pm_len - m_len);
    printf("pm_len-m_len:%d\n",pm_len-m_len);
	for (int i=0; i< pm_len - m_len; ++i)
		(m_block + m_len)[i] = 0;
	
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0 ; i < 8; i++) {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
}

















void write_inputfile(unsigned char *transaction,unsigned int start,unsigned int end, unsigned char*deleted_data,unsigned int input_size){
int i;
FILE *file;
file=fopen("hash.bc.in","w");
for (i=0;i<TRANSACTION_LENGTH;i++) fprintf(file,"%u\n",transaction[i]);
fprintf(file,"%u\n",start);
fprintf(file,"%u\n",end);
fprintf(file,"%u\n",input_size);
for (i=0;i<DELETED_DATA_LENGTH;i++) fprintf(file,"%u\n",deleted_data[i]);
}
void _write_j1inputfile(unsigned char*digest,unsigned char *transaction,unsigned int transaction_length,unsigned int *start,unsigned int *end,unsigned int input_size){
int i;
FILE *file;
file=fopen("hashverif.j1.in","w");
fprintf(file,"%s","{\"inputs\":["); 
for (i=0;i<transaction_length;i++) {
	
	if (i!=0) fprintf(file,"%s",",");
	fprintf(file,"\"%u\"",(int)transaction[i]);
}
	fprintf(file,"%s",",");
for (;i<transaction_length+SAFE_BOUND;i++) fprintf(file,"\"%u\",",0); 
for (i=0;i<transaction_length;i++){
fprintf(file,"\"%u\",",start[i]); 
fprintf(file,"\"%u\",",end[i]); 
}
fprintf(file,"\"%u\",",input_size); 
for (i=0;i<DIGEST_SIZE;i++){
	if (i!=0) fprintf(file,"%s",",");
	fprintf(file,"\"%u\"",(int)digest[i]);
}
fprintf(file,"%s","]}"); 
fflush(file);
fclose(file);
}

void _write_inputfile(unsigned char *transaction,unsigned int transaction_length,unsigned int *start, unsigned int *end,unsigned  int deleted_data_length,unsigned char*deleted_data,unsigned int input_size){
int i;
FILE *file;
file=fopen("hash.bc.in","w");
for (i=0;i<transaction_length;i++) {
	
	fprintf(file,"%u\n",(int)transaction[i]);
}
for (;i<transaction_length+SAFE_BOUND;i++) fprintf(file,"%u\n",0);
for (i=0;i<transaction_length;i++){
fprintf(file,"%u\n",start[i]); 
fprintf(file,"%u\n",end[i]); 
}
fprintf(file,"%u\n",input_size); 
for (i=0;i<deleted_data_length;i++){
       	fprintf(file,"%u\n",(int) deleted_data[i]);
}
fflush(file);
fclose(file);
}

void GenerateStatementWitness(unsigned char*transaction,unsigned int transaction_length,unsigned int *start,unsigned int *end,unsigned int deleted_data_length,unsigned char*deleted_data,unsigned int input_size){

_write_inputfile(transaction,transaction_length,start,end,deleted_data_length,deleted_data,input_size);
}

void GenerateStatement(unsigned char *digest,unsigned char*transaction,unsigned int transaction_length,unsigned int *start,unsigned int *end,unsigned int input_size){

_write_j1inputfile(digest,transaction,transaction_length,start,end,input_size);
}

void GenerateCircuit(unsigned int transaction_length,unsigned int deleted_data_length){
	pid_t childpid;
	char *argv[4];
	argv[0]=(char *)calloc(30,1);
	argv[1]=(char *)calloc(30,1);
	argv[2]=(char *)calloc(30,1);
	sprintf(argv[0],"./hashgeneratecircuit.sh");
	sprintf(argv[1],"%d",transaction_length);
	sprintf(argv[2],"%d",deleted_data_length);
	argv[3]=NULL;
childpid=fork();
if (childpid==0) execve("./hashgeneratecircuit.sh",argv,NULL);

}
void GenerateCircuitStatementWitness(unsigned char* transaction,unsigned int transaction_length,unsigned int *start,unsigned int *end,unsigned int deleted_data_length,unsigned char*deleted_data,unsigned int input_size){
GenerateStatementWitness(transaction,transaction_length,start,end,deleted_data_length,deleted_data,input_size);
GenerateCircuit(transaction_length,deleted_data_length);
}



void Prover(unsigned char* transaction,unsigned int transaction_length,unsigned int *start,unsigned int *end,unsigned int deleted_data_length,unsigned char*deleted_data,unsigned int input_size){
	pid_t childpid;
	char *argv[2];
	argv[0]=(char *)calloc(30,1);
	sprintf(argv[0],"./hashprover.sh");
	//sprintf(argv[1],"-c");
	argv[1]=NULL;
_write_inputfile(transaction,transaction_length,start,end,deleted_data_length,deleted_data,input_size);
childpid=fork();
if (childpid==0) execve("./hashprover.sh",argv,NULL);

}

void Verifier(void){	
char *argv[2];
	argv[0]=(char *)calloc(30,1);
	sprintf(argv[0],"./hashverif.sh");
	argv[1]=NULL;
execv("./hashverif.sh",argv);

}


int main(int argc,char*argv[]){
	FILE *f;
	unsigned char*transaction,*deleted_data,*digest;
	unsigned int i,j,k,length,deleted_data_length,*start,*end,input_size;
	SHA256 ctx;

	
	
	
	//write_inputfile(transaction,deleted_data);
	//
	//
	//
	if (argv[1]==NULL) { printf("missing parameters - read README file\n");return 0;}
		switch(argv[1][0]){

			case 'C':
	if (argv[2]==NULL) { printf("missing parameters - read README file\n");break;}
	if (argv[3]==NULL) { printf("missing parameters - read README file\n");break;}
				length=atoi(argv[2]);
				deleted_data_length=atoi(argv[3]);
				GenerateCircuit(length,deleted_data_length);
				break;
				
		case 'W':
				length=atoi(argv[2]);
				start=(unsigned int *) calloc(length,sizeof(unsigned int));
				end=(unsigned int *)calloc(length,sizeof(unsigned int));
				k=3;
				for (i=0;i<length;i++){
				start[i]=atoi(argv[k++]);
				end[i]=atoi(argv[k++]);
				}
				deleted_data_length=atoi(argv[k++]);
				input_size=atoi(argv[k++]);
				
				transaction=(unsigned char *) calloc(length+1,1);
				f=fopen("transaction","rb");
fread(transaction,1,length,f);
				deleted_data=(unsigned char *) calloc(deleted_data_length+1,1);
				f=fopen("deleted_data","rb");
fread(deleted_data,1,deleted_data_length,f);
GenerateCircuitStatementWitness(transaction,length,start,end,deleted_data_length,deleted_data,input_size);
break;

		case 'S':
				length=atoi(argv[2]);
				start=(unsigned int *)calloc(length,sizeof(unsigned int));
				end=(unsigned int *)calloc(length,sizeof(unsigned int));
				k=3;
				for (i=0;i<length;i++){
				start[i]=atoi(argv[k++]);
				end[i]=atoi(argv[k++]);
				}
				input_size=atoi(argv[k]);

				digest=(unsigned char *) calloc(DIGEST_SIZE,1);
				f=fopen("digest","rb");
fread(digest,1,DIGEST_SIZE,f);
				transaction=(unsigned char *) calloc(length+1,1);
				f=fopen("transaction","rb");
fread(transaction,1,length,f);


				GenerateStatement(digest,transaction,length,start,end,input_size); 
break;

		case 'P':
				length=atoi(argv[2]);
				start=(unsigned int *)calloc(length,sizeof(unsigned int));
				end=(unsigned int *)calloc(length,sizeof(unsigned int));
				k=3;
				for (i=0;i<length;i++){
				start[i]=atoi(argv[k++]);
				end[i]=atoi(argv[k++]);
				}
				deleted_data_length=atoi(argv[k++]);
				input_size=atoi(argv[k]);
				
				transaction=(unsigned char *) calloc(length+1,1);
				f=fopen("transaction","rb");
fread(transaction,1,length,f);
				deleted_data=(unsigned char *) calloc(deleted_data_length+1,1);
				f=fopen("deleted_data","rb");
fread(deleted_data,1,deleted_data_length,f);

Prover(transaction,length,start,end,deleted_data_length,deleted_data,input_size);
	break;

		case 'H':
	 
				length=atoi(argv[2]);
				k=3;
				start=(unsigned int*)calloc(length,sizeof(unsigned int));
				end=(unsigned int *)calloc(length,sizeof(unsigned int));
				for (i=0;i<length;i++){
				start[i]=atoi(argv[k++]);
				end[i]=atoi(argv[k++]);
				}
				deleted_data_length=atoi(argv[k++]);
				input_size=atoi(argv[k++]);

				transaction=(unsigned char *) calloc(length+1,1);
				f=fopen("transaction","rb");
fread(transaction,1,length,f);
				deleted_data=(unsigned char *) calloc(deleted_data_length+1,1);
				f=fopen("deleted_data","rb");
fread(deleted_data,1,deleted_data_length,f);

	digest=(unsigned char*) calloc(DIGEST_SIZE+1,1);
/*
 * for (i=0;i<deleted_data_length;i++) {
	j=start+i;
	if (j<=end) transaction[j]=deleted_data[i];
}
*/
	/*
printf("length:%u\n",length);
for (i=0;i<length;i++) printf("%d %x ",i,transaction[i]);
printf("\n");
printf("deleted_data_length:%u\n",deleted_data_length);
for (i=0;i<deleted_data_length;i++) printf("%d %x ",i,deleted_data[i]);
printf("\n");
	  
*/
	for (i=j=k=0;i<length;i++) {
		    if (i>=start[j] && i<=end[j]) transaction[i]=deleted_data[k++];
		    if (i>=end[j]) j++;
}
/*
printf("length:%u\n",length);
for (i=0;i<length;i++) printf("%d %x ",i,transaction[i]);
printf("\n");
*/
    ctx.update(transaction, input_size);
    ctx.final(digest);


f=fopen("digest","wb");
fwrite(digest,1,DIGEST_SIZE,f);
break;
case 'V':
Verifier();
	}
return 0;

}



