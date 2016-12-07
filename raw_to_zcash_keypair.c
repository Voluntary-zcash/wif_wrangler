/*
raw_to_zcash_keypair.c version 0.01 was created on the 3rd of December 2016 by Voluntary.  

The signature file, raw_to_zcash_keypair.c.asc, can be checked against: 



Install libssl-dev and compile with: 

 > gcc raw_to_zcash_keypair.c -o raw2zkp -Wall -lcrypto

I learned about the following value by studying Matt Whitlock's diceware.c - 

static const uint32_t secp256k1_n[8] = {0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL, 0xBAAEDCE6UL, 0xAF48A03BUL, 0xBFD25E8CUL, 0xD0364141UL};

https://vimeo.com/123798651 Bitcoin diceware on a TI-89 graphing calculator

The following link and excerpt were also quite instructive: 

https://en.bitcoin.it/w/index.php?title=Technical_background_of_Bitcoin_addresses&redirect=no

How to create Bitcoin Address

0 - Having a private ECDSA key

   18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725

1 - Take the corresponding public key generated with it (65 bytes, 1 byte 0x04, 32 bytes corresponding to X coordinate, 32 bytes corresponding to Y coordinate)

   0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6

2 - Perform SHA-256 hashing on the public key

   600FFE422B4E00731A59557A5CCA46CC183944191006324A447BDB2D98D4B408

3 - Perform RIPEMD-160 hashing on the result of SHA-256

   010966776006953D5567439E5E39F86A0D273BEE

4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)

   00010966776006953D5567439E5E39F86A0D273BEE

(note that below steps are the Base58Check encoding, which has multiple library options available implementing it)
5 - Perform SHA-256 hash on the extended RIPEMD-160 result

   445C7A8007A93D8733188288BB320A8FE2DEBD2AE1B47F0F50BC10BAE845C094

6 - Perform SHA-256 hash on the result of the previous SHA-256 hash

   D61967F63C7DD183914A4AE452C9F6AD5D462CE3D277798075B107615C1A8A30

7 - Take the first 4 bytes of the second SHA-256 hash. This is the address checksum

   D61967F6

8 - Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.

   00010966776006953D5567439E5E39F86A0D273BEED61967F6

9 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format

   16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM

However, the above example is for an uncompressed public key which is specified by a 
WIF encoded private key with no flag byte suffix.  

https://bitcoin.stackexchange.com/questions/23387/why-can-addresses-be-shorter-than-34-bytes
*/

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

	BIGNUM *bn_input;
	BIGNUM *bn_secp256k1_n;
	BIGNUM *bn_58;
	BIGNUM *bn_power_of_58;
	BIGNUM *bn_dividend;
	BIGNUM *bn_scratch;

	BN_CTX *ctx;

	BIGNUM *bn_public_key;

	EC_KEY *ec_private_key;
	const EC_GROUP *ec_group;
	EC_POINT *ec_public_key_point;

	// Storing this value (and other big numbers) as an array of bytes 
	// seems to be the way to get around little-endian issues...  
	unsigned char secp256k1_n[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 
					0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 
					0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}, 
			scratch_array[56] = {0}, sha256_output[32] = {0};

void initialise(void)
{
	bn_input = BN_new();
	bn_secp256k1_n = BN_new();
	bn_58 = BN_new();
	bn_power_of_58 = BN_new();
	bn_dividend = BN_new();
	bn_scratch = BN_new();

	ctx = BN_CTX_new();

	bn_public_key = BN_new();

	ec_private_key = EC_KEY_new_by_curve_name(NID_secp256k1);
	ec_group = EC_KEY_get0_group(ec_private_key);
	ec_public_key_point = EC_POINT_new(ec_group);

	BN_dec2bn(&bn_58, "58");

	BN_bin2bn(secp256k1_n, 32, bn_secp256k1_n);
}

void clean_up(void)
{
	BN_clear_free(bn_input);
	BN_clear_free(bn_secp256k1_n);
	BN_clear_free(bn_58);
	BN_clear_free(bn_power_of_58);
	BN_clear_free(bn_dividend);
	BN_clear_free(bn_scratch);

	BN_CTX_free(ctx);

	BN_clear_free(bn_public_key);

	EC_KEY_free(ec_private_key);	// Not sure but this seems to also free ec_group...  
//	EC_GROUP_free(ec_group);
	EC_POINT_clear_free(ec_public_key_point);
}

void wif_it(int i)
{
	SHA256(scratch_array, i, sha256_output);
	SHA256(sha256_output, 32, sha256_output);

	scratch_array[i + 0] = sha256_output[0];
	scratch_array[i + 1] = sha256_output[1];
	scratch_array[i + 2] = sha256_output[2];
	scratch_array[i + 3] = sha256_output[3];

	BN_bin2bn(scratch_array, i + 4, bn_scratch);

	BN_dec2bn(&bn_power_of_58, "1");

	// Increase the power of 58 until it is greater than bn_scratch.  
	while(BN_cmp(bn_scratch, bn_power_of_58) > 0)
		BN_mul(bn_power_of_58, bn_power_of_58, bn_58, ctx);

	// Wind back bn_power_of_58 to make it either less than or equal to bn_scratch.  
	for(i = 0, BN_div(bn_power_of_58, NULL, bn_power_of_58, bn_58, ctx); !BN_is_zero(bn_power_of_58); i++)
	{
		BN_div(bn_dividend, bn_scratch, bn_scratch, bn_power_of_58, ctx);

		if(BN_is_zero(bn_dividend))	// BN_bn2bin() seems to mishandle 
			sha256_output[0] = 0;	// the result if BIGNUM = 0
		else	BN_bn2bin(bn_dividend, sha256_output);

		// Convert to a base58 character.  
		if(sha256_output[0] < 9)
			scratch_array[i] = sha256_output[0] + '1';
		else if(sha256_output[0] < 17)
			scratch_array[i] = sha256_output[0] + ('A' - 9);
		else if(sha256_output[0] < 22)
			scratch_array[i] = sha256_output[0] + ('J' - 17);
		else if(sha256_output[0] < 33)
			scratch_array[i] = sha256_output[0] + ('P' - 22);
		else if(sha256_output[0] < 44)
			scratch_array[i] = sha256_output[0] + ('a' - 33);
		else if(sha256_output[0] < 58)
			scratch_array[i] = sha256_output[0] + ('m' - 44);
		else	printf("\n\tWIF encoding error.  "
			"Character input value = %d\n", sha256_output[0]);
			// The error response to values >= 58 should be better than this...  

		// Create the next lowest power of 58.  
		BN_div(bn_power_of_58, NULL, bn_power_of_58, bn_58, ctx);
	}

	scratch_array[i] = 0;		// Put a NULL byte at the end of the string.  
	printf("%s\n", scratch_array);
}

int main(int argc, char **argv)
{
	initialise();

	int i;

	if(argc == 2)
	{
		i = BN_hex2bn(&bn_input, argv[1]);

		if(i < 64)
			printf("Input provided %d of 256 bits.\n", i * 4);

		if(BN_cmp(bn_secp256k1_n, bn_input) != 1)
		{
			printf("Please input a value less than:\n%s\n", 
				BN_bn2hex(bn_secp256k1_n));
		}
		else
		{
			BN_hex2bn(&bn_scratch, "80");		// Private key prefix byte.  
			BN_lshift(bn_scratch, bn_scratch, 256);	// Make space for
			BN_add(bn_scratch, bn_scratch, bn_input); // the private key.  
			BN_lshift(bn_scratch, bn_scratch, 8);	// Make space for the flag 
			BN_set_bit(bn_scratch, 0);		// byte and set its least 
			// significant bit (0x01).  A flag byte of 0x01 indicates that this 
			// private key corresponds to a compressed public key.  

			BN_bn2bin(bn_scratch, scratch_array);

			wif_it(34);	// Prefix byte + 32 private key bytes + flag byte.  

			// ***************

			EC_KEY_set_private_key(ec_private_key, bn_input);
			EC_POINT_mul(ec_group, ec_public_key_point, bn_input, NULL, NULL, ctx);
			bn_public_key = EC_POINT_point2bn(ec_group, ec_public_key_point, 
					POINT_CONVERSION_COMPRESSED, bn_public_key, ctx);

			SHA256(scratch_array, 
				BN_bn2bin(bn_public_key, scratch_array), sha256_output);
			RIPEMD160(sha256_output, 32, scratch_array + 2); // Two prefix bytes.  

			scratch_array[0] = 0x1c;	// These are the prefix bytes 
			scratch_array[1] = 0xb8;	// for a Zcash t_address.  

			wif_it(22);	// Two prefix bytes + 20 byte RIPEMD160 hash.  
		}
	}
	else 	printf("Please input a single string of 64 hexadecimal\n"
			"characters such as shasum -a 256 outputs.\n");
	clean_up();

	return(0);
}
