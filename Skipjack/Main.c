#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <climits>

#include "SHA1.h"
#include "Skipjack.h"
#include "Mersenne.h"

#define BUFSIZE 4096

int main()
{
	char* locale = setlocale(LC_ALL, "");
	SHA1_CTX context;
	byte digest[20], buffer[BUFSIZE];
	FILE* ptr_file;

	if ((ptr_file = fopen("StartKey.txt", "w")) == NULL)
	{
		printf("Error opening file for writing");
		return 0;
	}
	else
	{
		sgenrand((unsigned long)time(NULL));
		unsigned int key_size = genrand() % 270;
		byte* key = malloc(key_size);

		if (key_size != 0)
		{
			if (key)
			{
				for (int i = 0; i < key_size; i++)
				{
					key[i] = genrand() % 256;
				}

				printf("Start key:\t\t");
				for (int i = 0; i < key_size; i++)
				{
					if (i != 0 && i % 30 == 0) { printf("\n\t\t\t"); }
					printf("%02X", key[i-1]);
				}
				putchar('\n');
				putchar('\n');

				fwrite(key, sizeof(byte), key_size, ptr_file);
				free(key);
			}
		}

		fclose(ptr_file);
	}

	if ((ptr_file = fopen("StartKey.txt", "r")) == NULL)
	{
		printf("Error opening file for reading");
		return 0;
	}
	else
	{
		SHA1Init(&context);

		int key_lenght;
		while (!feof(ptr_file))
		{
			key_lenght = fread(buffer, 1, BUFSIZE, ptr_file);
			SHA1Update(&context, buffer, key_lenght);
		}

		fclose(ptr_file);
	}

	SHA1Final(digest, &context);

	if ((ptr_file = fopen("Digest.txt", "w")) == NULL)
	{
		printf("Error opening file for writing");
		return 0;
	}
	else
	{
		fwrite(digest, sizeof(byte), 20, ptr_file);
		fclose(ptr_file);
	}


	byte key[10];
	byte inp[8], enc[8], dec[8];
	byte tab[10][256];

	for (int i = 0; i < 10; i++)
	{
		key[i] = digest[i + 10];
	}	

	makeKey(key, tab);

	int length_text;
	if ((ptr_file = fopen("Text.txt", "r+")) == NULL)
	{
		printf("Error opening file for reading");
		return 0;
	}
	else
	{
		fseek(ptr_file, 0, SEEK_END);
		length_text = ftell(ptr_file);
		fclose(ptr_file);
	}
	int num_blocks = (int)(length_text / 8) + 1;
	int text_size = num_blocks * 8;

	byte* text = malloc(text_size);
	byte* encrypted_text = malloc(text_size);
	byte* decrypted_text = malloc(text_size);

	if (text && encrypted_text && decrypted_text )
	{
		for (int i = 0; i < text_size; i++)
		{
			text[i] = 0x00;
		}

		if ((ptr_file = fopen("Text.txt", "r+")) == NULL)
		{
			printf("Error opening file for reading");
			return 0;
		}
		else
		{
			fread(text, sizeof(byte), text_size, ptr_file);
			fclose(ptr_file);
		}


		for (int N = 0; N < num_blocks; N++)
		{
			for (int i = 0; i < 8; i++)
			{
				inp[i] = text[i + N * 8];
			}

			encrypt(tab, inp, enc);
			for (int i = 0; i < 8; i++)
			{
				encrypted_text[i + N * 8] = enc[i];
			}

			decrypt(tab, enc, dec);
			for (int i = 0; i < 8; i++)
			{
				decrypted_text[i + N * 8] = dec[i];
			}
		}


		if ((ptr_file = fopen("Encrypted.txt", "w+")) == NULL)
		{
			printf("Error opening file for writing");
			return 0;
		}
		else
		{
			fwrite(encrypted_text, sizeof(byte), text_size, ptr_file);
			fclose(ptr_file);
		}
		if ((ptr_file = fopen("Decrypted.txt", "w+")) == NULL)
		{
			printf("Error opening file for writing");
			return 0;
		}
		else
		{
			fwrite(decrypted_text, sizeof(byte), length_text, ptr_file);
			fclose(ptr_file);
		}


		printf("Digest (160 bit):\t");
		for (int i = 0; i < 20; i++)
		{
			if (i == 10) putchar(' ');
			printf("%02X", digest[i]);
		}
		putchar('\n');
		putchar('\n');
		printf("Secret key (80 bit):\t");
		for (int i = 0; i < 10; i++)
		{
			printf("%02X", key[i]);
		}
		putchar('\n');
		putchar('\n');
		printf("Text:\t\t\t%s\n", text);
		putchar('\n');
		printf("Text in HEX:\t\t");
		for (int i = 0; i < length_text; i++)
		{
			printf("%02X", text[i]);
		}
		putchar('\n');
		putchar('\n');
		printf("Encrypted text in HEX:\t");
		for (int i = 0; i < text_size; i++)
		{
			printf("%02X", encrypted_text[i]);
		}
		putchar('\n');
		putchar('\n');
		putchar('\n');
		printf("Decrypted text in HEX:\t");
		for (int i = 0; i < length_text; i++)
		{
			printf("%02X", decrypted_text[i]);
		}
		putchar('\n');
		putchar('\n');
		printf("Decrypted text:\t\t%s\n", decrypted_text);
		putchar('\n');
		printf((memcmp(text, decrypted_text, text_size) == 0) ? "Encryption and Decryption OK!\n" : "Decryption failure!\n");

		free(text);
		free(encrypted_text);
		free(decrypted_text);

	}
	else
	{
		printf("Error call mallok() function");
		return 0;
	}
	
	return 0;
}