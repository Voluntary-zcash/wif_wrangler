/*
wif_wrangler.c version 0.01 created by Voluntary on the 8th of December 2016.  

The signature file, wif_wrangler.c.asc, can be checked against: 

https://pgp.mit.edu/pks/lookup?op=get&search=0xF3F7E43D0FCD9A76

Public domain - use at your own risk.  Be sure to verify all output.  

wif_wrangler takes a Bitcoin address and converts it to a Zcash t_addrress.  

This is useful because Bitcoin and Zcash private keys are compatible.  If you 
have a Bitcoin private key for offline use (ie: cold storage), you can convert 
the matching Bitcoin address without exposing your private key.  

Compile with: 

 > gcc wif_wrangler.c -o wif_wrangler -Wall -lcrypto

Dependency: libssl-dev

This program has had VERY LIMITED testing - and only on Ubuntu 16.10 64bit.  

Interesting question and answer pertaining to Bitcoin address length limits: 
https://bitcoin.stackexchange.com/questions/23387/why-can-addresses-be-shorter-than-34-bytes
*/

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

int main(int argc, char **argv)
{
	// Only continue if there's a single argument.  
	if(argc == 2)
	{
		int i;
		unsigned char address[40] = {0};
		// Bitcoin addresses are up to 34 characters, 
		// Zcash addresses are 35.  Add a null byte for 
		// end-of-string - and some more bytes to bring the 
		// total to a multiple of eight in this 64 bit era...  

		// Ensure that argv[1][i] is a base58 character and 
		// convert it to an 8-bit integer in address[i].  
		for(i = 0; argv[1][i] != 0 && i < 34; i++)
		{
			if(argv[1][i] > '0' && argv[1][i] <= '9')
				address[i] = argv[1][i] - '1';
			else if(argv[1][i] >= 'A' && argv[1][i] < 'I')
				address[i] = argv[1][i] - ('A' - 9);
			else if(argv[1][i] > 'I' && argv[1][i] < 'O')
				address[i] = argv[1][i] - ('A' - 8);
			else if(argv[1][i] > 'O' && argv[1][i] <= 'Z')
				address[i] = argv[1][i] - ('A' - 7);
			else if(argv[1][i] >= 'a' && argv[1][i] < 'l')
				address[i] = argv[1][i] - ('a' - 33);
			else if(argv[1][i] > 'l' && argv[1][i] <= 'z')
				address[i] = argv[1][i] - ('a' - 32);
			else
			{
				// Just have a tantrum if there are non-base58 characters.  
				printf("\n\t'%c' is not a valid base58 character.\n\n", argv[1][i]);
				return(0);
			}
		}

		// If the above for-loop exits and argv[1][i] != 0 
		// then argv[1] must have more than 34 characters.  
		// Also, if i < 27 then argv[1] was too short.  
		if(argv[1][i] != 0 || i < 27)
		{
			printf("\n\tA Bitcoin address should be between 27 and 34 characters.\n\n");
			return(0);
		}

		BIGNUM *bn_58 = BN_new();
		BIGNUM *bn_power_of_58 = BN_new();
		BIGNUM *bn_base58_integer = BN_new();
		BIGNUM *bn_product = BN_new();
		BIGNUM *bn_accumulator = BN_new();

		BN_CTX *ctx = BN_CTX_new();		// Scratch space for BN_mul & BN_div.  

		// Initialise some BIGNUM values.  
		BN_dec2bn(&bn_58, "58");		// Used to create the powers of 58.  
		BN_dec2bn(&bn_power_of_58, "1");	// 1 = 58^0 which is used with the
		BN_dec2bn(&bn_accumulator, "0");	// least significant base58 digit.  

		// Pre-decrement i to bring it back to the least significant element of address[].  
		for(--i; i >= 0; i--)
		{
			// Convert each byte in address[] to a BIGNUM, 
			// beginning with the least significant.  
			BN_bin2bn(&address[i], 1, bn_base58_integer);

			// Then multiply by the appropriate power of 58.  
			BN_mul(bn_product, bn_base58_integer, bn_power_of_58, ctx);

			// Then add the above product to the accumulator.  
			BN_add(bn_accumulator, bn_accumulator, bn_product);

			// Then generate the next power of 58.  
			BN_mul(bn_power_of_58, bn_power_of_58, bn_58, ctx);
		}

		BN_bn2bin(bn_accumulator, &address[26 - BN_num_bytes(bn_accumulator)]);
		// This will cause the least significant byte 
		// of bn_accumulator to allign to address[25].  

		// For every leading base58 '1' in argv[1], 
		// ensure there is a leading null byte in address[].  
		for(i = 0; argv[1][i] == '1'; address[i + 1] = 0, i++);

		unsigned char hash_buffer[32] = {0};

		// A WIF checksum is a double SHA256 hash.  The first hash is 
		// composed of the prefix byte and the 20 byte (or 160 bit) 
		// RIPEMD160 hash of the SHA256 hash of the public key 
		// generated from the 256 bit private key.  
		SHA256(&address[1], 21, hash_buffer);

		// The second hash is composed from the 32 bytes (or 256 bits) of 
		// the first hash.  The checksum only uses the first 32 bits...  
		SHA256(hash_buffer, 32, hash_buffer);

		// Does the user input derived checksum match the first 
		// four bytes of the newly calculated double SHA256 hash?  
		if(address[22] == hash_buffer[0]
		&& address[23] == hash_buffer[1]
		&& address[24] == hash_buffer[2]
		&& address[25] == hash_buffer[3])
		{
			printf("\n\tGood checksum.  ");

			address[0] = 0x1c;			// These are the Zcash 
			address[1] = 0xb8;			// t_addr prefix bytes.  

			SHA256(address, 22, hash_buffer);	// Create the double SHA256 
			SHA256(hash_buffer, 32, hash_buffer);	// WIF checksum.  

			address[22] = hash_buffer[0];		// Append the first 32 bits 
			address[23] = hash_buffer[1];		// (or four bytes) to the 
			address[24] = hash_buffer[2];		// preceding address bytes.  
			address[25] = hash_buffer[3];

			// Create a BIGNUM from the raw address data.  
			BN_bin2bn(address, 26, bn_accumulator);

			// Increase bn_power_of_58 until it is larger than bn_accumulator.  
			while(BN_cmp(bn_power_of_58, bn_accumulator) != 1)
				BN_mul(bn_power_of_58, bn_power_of_58, bn_58, ctx);

			// bn_power_58 is now one power of 58 larger than needed.  

			// Convert bn_accumulator to base58 characters in address[].  
			for(i = 0; i < 35; i++)
			{
				// Create the next lowest power of 58.  
				BN_div(bn_power_of_58, bn_base58_integer, 
					bn_power_of_58, bn_58, ctx);

				// Divide bn_accumulator by bn_power_of_58.  Place the result 
				// in bn_base58_integer and the remainder in bn_accumulator.  
				BN_div(bn_base58_integer, bn_accumulator, 
					bn_accumulator, bn_power_of_58, ctx);

				// Something weird happens with BN_bn2bin() when the BIGNUM = 0
				if(BN_is_zero(bn_base58_integer))
					address[i] = 0;
				else	BN_bn2bin(bn_base58_integer, &address[i]);

				// Convert to a base58 character.  
				if(address[i] < 9)
					address[i] += '1';
				else if(address[i] < 17)
					address[i] += ('A' - 9);
				else if(address[i] < 22)
					address[i] += ('J' - 17);
				else if(address[i] < 33)
					address[i] += ('P' - 22);
				else if(address[i] < 44)
					address[i] += ('a' - 33);
				else if(address[i] < 58)
					address[i] += ('m' - 44);
				else
				{
					printf("\n\tBase58 encoding error.  "
					"Character input value = %d\n", (int) address[i]);

					return(0);	// No clean-up...  
				}
			}
			printf("The equivalent Zcash address is: %s\n"
				"\n\tBe sure to verify this address before using it.\n\n", address);
		}
		else	printf("\n\tUnable to confirm the checksum.\n\n");

		// Clean-up.  
		BN_clear_free(bn_58);
		BN_clear_free(bn_power_of_58);
		BN_clear_free(bn_base58_integer);
		BN_clear_free(bn_product);
		BN_clear_free(bn_accumulator);
		BN_CTX_free(ctx);
	}
	else	printf("\n\tEnter a single Bitcoin address as the argument.\n\n");

	return(0);
}
