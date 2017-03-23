#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"
#define Blocksize 64
#define o_key 0x5c
#define i_key 0x36




static int
validate(char * secret_hex, uint8_t *m, char * OTP_string)
{
	int i,j;
	int key_length = strlen(secret_hex);
	uint8_t hmac_key[Blocksize];

	uint8_t ipad[65]; /* inner padding - key XORd with ipad */
    uint8_t opad[65];

	for (i=0; i<(key_length/2);i++){
		sscanf(secret_hex+2*i, "%02x", &hmac_key[i]);
	}
	
	for(i=key_length/2; i<Blocksize; i++){
		hmac_key[i]= 0x00;
	}

    
	uint8_t o_key_pad[Blocksize];
	uint8_t i_key_pad[Blocksize];
	

	for(i=0; i<Blocksize; i++){
		o_key_pad[i] = o_key ^ hmac_key[i];
		i_key_pad[i] = i_key ^ hmac_key[i];
	}

	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx);
	sha1_update(&ctx, i_key_pad, Blocksize);
	sha1_update(&ctx, m, 8);
	sha1_final(&ctx, sha);


	uint8_t shaout[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, o_key_pad, Blocksize);
	sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, shaout);
	
	int offset   =  shaout[19] & 0xf ;
    int bin_code = (shaout[offset]  & 0x7f) << 24
           | (shaout[offset+1] & 0xff) << 16
           | (shaout[offset+2] & 0xff) <<  8
           | (shaout[offset+3] & 0xff) ;

    long hotp_val = bin_code % 1000000;
    
    long val = atoi(OTP_string);
    if(val == hotp_val){
    	return 1;
    }
    else return (0);
}


static int
validateHOTP(char * secret_hex, char * HOTP_string){
	int i;
	long counter=1;
	uint8_t text[sizeof(counter)];
	for(i=sizeof(text)-1; i>=0; i--){
		text[i] = (char)(counter & 0xff);
		counter >>=8;
	}
	for(i=0; i<8; i++){
		printf("text: %d\n", text[i]);
	}
	return validate(secret_hex, text, HOTP_string);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int t = ((int)time(NULL))/30; // period = 30

    int i;
    uint8_t timer[8]; 
    for( i = 7; i >= 0 ; i--){
        timer[i] = t & 0xff;
        t >>= 8;
    }
    return validate(secret_hex, timer, TOTP_string);
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
