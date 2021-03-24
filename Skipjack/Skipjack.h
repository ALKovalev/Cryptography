typedef unsigned char	byte;
typedef unsigned short int	word16;

extern void makeKey(byte[], byte[][256]);
extern void encrypt(byte[][256], byte[], byte[]);
extern void decrypt(byte[][256], byte[], byte[]);


