#pragma warning(disable : 4996)

typedef struct {
    unsigned long state[5];
    unsigned long count[2];
    unsigned char buffer[64];
} SHA1_CTX;

extern void SHA1Transform(unsigned long[], unsigned char[]);
extern void SHA1Init(SHA1_CTX*);
extern void SHA1Update(SHA1_CTX*, unsigned char*, unsigned int);
extern void SHA1Final(unsigned char[], SHA1_CTX*);