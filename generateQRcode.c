#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];
	char * hotp_url;
	char * totp_url;
	int i,j;

	int secret_length = strlen(secret_hex);

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	//adding zeros to the secret if the length of the secret is smaller than 20
	char gen_secret[20];
	int zerolength;
	zerolength = 20 - secret_length;
	if (zerolength > 0){
		for (i=0; i<zerolength; i++){
			gen_secret[i] = '0';
		}
		for(i; i<20; i++){
			gen_secret[i] = secret_hex[i-zerolength];
		}
	}
	else{
		for (i=0; i<20; i++){
			gen_secret[i] = secret_hex[i];
		}
	}
	gen_secret[20] = '\0';

	//string to bite array
	uint8_t secretarr[10];
	uint8_t secretarr_length = strlen(gen_secret);

	for (i=0; i<(secretarr_length/2);i++){
		sscanf(gen_secret+2*i, "%02x", &secretarr[i]);
	}
	

	const char *encode_issuer = urlEncode(issuer);
	const char *encode_accountName = urlEncode(accountName);
	char encode_secret[100];

	int secretencode = base32_encode((uint8_t *) secretarr, 10, (uint8_t *) encode_secret, 100);

	int hotp_len = 100;
	int totp_len = 100;
	hotp_url = (char *) malloc(hotp_len * sizeof(char));
	totp_url = (char *) malloc(totp_len * sizeof(char));

	snprintf(hotp_url, hotp_len, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encode_accountName, encode_issuer, encode_secret);
	displayQRcode(hotp_url);


	snprintf(totp_url, totp_len, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encode_accountName, encode_issuer, encode_secret);
	displayQRcode(totp_url);

	free(hotp_url);
	free(totp_url);


	return (0);
}
