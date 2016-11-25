/*
wif_wrangler.c created by voluntary on the 26th November 2016

Public domain - use at your own risk.  Be sure to verify all output.  

wif_wrangler takes a 34 character bitcoin address and converts it 
to a 35 character Zcash t_addrress.  

Compile with: 

 > gcc wif_wrangler.c -o wif_wrangler -Wall -lcrypto

Dependency: libssl-dev

This program has had VERY LIMITED testing - and only on Ubuntu 16.10
*/

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

int main(int argc, char **argv)
{
	// Only do this if there's a single argument 
	// and it is 34 characters long.  
	if(argc == 2 && strlen(argv[1]) == 34)
	{
		// Output buffer(s).  
		unsigned char a[64] = {0};
		unsigned char b[32] = {0};
		unsigned char c[32] = {0};

		int i;

		// Ensure that argv[1] is a WIF string and 
		// convert each WIF character to an 8-bit integer in a[].  
		for(i = 0; argv[1][i] != 0; i++)
		{
			if(argv[1][i] > '0' && argv[1][i] <= '9')
				a[i] = argv[1][i] - '1';
			else if(argv[1][i] >= 'A' && argv[1][i] < 'I')
				a[i] = argv[1][i] - ('A' - 9);
			else if(argv[1][i] > 'I' && argv[1][i] < 'O')
				a[i] = argv[1][i] - ('A' - 8);
			else if(argv[1][i] > 'O' && argv[1][i] <= 'Z')
				a[i] = argv[1][i] - ('A' - 7);
			else if(argv[1][i] >= 'a' && argv[1][i] < 'l')
				a[i] = argv[1][i] - ('a' - 33);
			else if(argv[1][i] > 'l' && argv[1][i] <= 'z')
				a[i] = argv[1][i] - ('a' - 32);
			else
			{
				// Just have a tantrum if there are non-WIF characters.  
				printf("\n\t'%c' is not a valid WIF character.\n\n", argv[1][i]);
				return(0);
			}
		}

		// Ascii buffer for 8-bit integer, BIGNUM ascii string pointer.  
		char ascii_int[4], *big_number_int_string;

		BIGNUM *bn_58 = BN_new();		// Used to create the powers of 58.  
		BIGNUM *bn_power_of_58 = BN_new();
		BIGNUM *bn_wif_integer = BN_new();

		BN_CTX *ctx = BN_CTX_new();
		BIGNUM *bn_product = BN_new();

		BIGNUM *bn_accumulator = BN_new();

		// Create the BIGNUM constant(s).  
		BN_dec2bn(&bn_58, "58");

		// Initialise the accumulator and power_of_58.  
		BN_dec2bn(&bn_accumulator, "0");
		BN_dec2bn(&bn_power_of_58, "1");	// 1 = 58^0 which is used with 
							// the least significant WIF digit.  
		for(i = strlen(argv[1]) - 1; i >= 0; i--)
		{
			// Beginning with the least significant converted WIF byte, 
			// convert each byte in a[] a hexadecimal ascii string.  
			sprintf(ascii_int, "%x", (int) a[i]);

			// Then convert that string to a BIGNUM.  
			BN_hex2bn(&bn_wif_integer, ascii_int);

			// Then multiply by the appropriate power of 58.  
			BN_mul(bn_product, bn_wif_integer, bn_power_of_58, ctx);

			// Then add the above product to the accumulator.  
			BN_add(bn_accumulator, bn_accumulator, bn_product);

			// Then generate the next power of 58.  
			BN_mul(bn_power_of_58, bn_power_of_58, bn_58, ctx);
		}

		BN_rshift(bn_wif_integer, bn_accumulator, 32);
		// bn_wif_integer = bn_accumulator without the checksum bits.  

		BN_mask_bits(bn_accumulator, 32);
		// Mask out non-checksum bits from bn_accumulator.  

		big_number_int_string = BN_bn2hex(bn_accumulator);
		// Ascii hexadecimal representation of bn_accumulator.  

		// Zcash addresses have two prefix bytes so leave a[0] unused.  
		a[1] = 0;				// Bitcoin address have a 
		BN_bn2bin(bn_wif_integer, a + 2);	// 0x00 prefix byte which 
							// is not preserved by BN_bn2bin()...  

		// A bitcoin address WIF checksum is a double SHA256 hash.  
		// The first hash is composed of the prefix byte and the 20 byte 
		// (or 160 bit) RIPEMD160 hash of the SHA256 hash of the actual 
		// public key generated from the 256 bit private key.  
		SHA256(a + 1, 21, b);

		// The second hash is composed from the 32 bytes (or 256 bits) of 
		// the first hash.  The checksum only uses the first 32 bits...  
		SHA256(b, 32, c);

		int entered_checksum, base58_digit;

		sscanf(big_number_int_string, "%x", &entered_checksum);

		// Does the entered checksum equal the first four bytes 
		// of the SHA256 hash that was just created in c[]?  
		if(entered_checksum == ((unsigned int) c[0] << 24)
					 + ((unsigned int) c[1] << 16)
					 + ((unsigned int) c[2] << 8)
					 + ((unsigned int) c[3]))
		{
			printf("\n\tGood checksum.  ");

			a[0] = 0x1c;		// These are the Zcash 
			a[1] = 0xb8;		// t_addr prefix bytes.  

			SHA256(a, 22, b);	// Create the double SHA256 
			SHA256(b, 32, c);	// WIF checksum.  

			a[22] = c[0];		// Append the first 32 bits 
			a[23] = c[1];		// (or four bytes) to the 
			a[24] = c[2];		// preceding address bytes.  
			a[25] = c[3];

			// Create a BIGNUM from the raw address data.  
			BN_bin2bn(a, 26, bn_accumulator);

			// Convert to base58.  
			for(i = 0; i < 35; i++)
			{
				// bn_power_of_58 already contains the appropriate 
				// power of 58 for a 35 character WIF string.  
				BN_div(bn_wif_integer, bn_accumulator, bn_accumulator, bn_power_of_58, ctx);

// Something weird happens with BN_bn2bin() when bn_wif_integer = 0
// ~ So BN_bn2hex() followed by sscanf() is just a work-around...  

				big_number_int_string = BN_bn2hex(bn_wif_integer);
				sscanf(big_number_int_string, "%x", &base58_digit);

				// Create the next lowest power of 58.  
				BN_div(bn_power_of_58, bn_wif_integer, bn_power_of_58, bn_58, ctx);

				// Convert to a WIF character.  
				if(base58_digit < 9)
					base58_digit += '1';
				else if(base58_digit < 17)
					base58_digit += ('A' - 9);
				else if(base58_digit < 22)
					base58_digit += ('J' - 17);
				else if(base58_digit < 33)
					base58_digit += ('P' - 22);
				else if(base58_digit < 44)
					base58_digit += ('a' - 33);
				else if(base58_digit < 58)
					base58_digit += ('m' - 44);
				else
				{
					printf("\n\tWIF encoding error.  "
					"Character input value = %d\n", base58_digit);

					return(0);
				}

				a[i] = (unsigned char) base58_digit;
			}
				printf("The equivalent Zcash address is %s\n\n"
				"\tBe sure to verify this address before using it.\n\n", a);
		}
		else
			printf("\n\tUnable to confirm the checksum.\n\n");

		// Clean-up.  
		OPENSSL_free(big_number_int_string);
		BN_clear_free(bn_58);
		BN_clear_free(bn_power_of_58);
		BN_clear_free(bn_wif_integer);
		BN_clear_free(bn_product);
		BN_clear_free(bn_accumulator);
		BN_CTX_free(ctx);
	}
	else
		printf("\n\tEnter a single, 34 character Bitcoin address as the argument.\n\n");

	return(0);
}
