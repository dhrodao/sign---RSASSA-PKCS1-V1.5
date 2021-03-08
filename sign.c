/**RSASSA-PKCS1 V1.5 Cipher/Validator*****************************************
  File        sign.c
  Resume      RSASSA-PKCS1 V1.5 Cipher/Validator
  Autor       Daniel Hervás Rodao
  Copyright (c) 2021 Daniel Hervás Rodao
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

enum{
	MAXBUFF = 1024,
	ID_LENGTH = 19,
	SIGN_LENGTH = 512,
	PS_LENGTH = 4096/8 - (ID_LENGTH + SHA512_DIGEST_LENGTH),
	PAD_LENGTH = SIGN_LENGTH-SHA512_DIGEST_LENGTH,	
};

// Define signature structure
typedef struct Signature Signature;
struct Signature{
	int len;
	unsigned char *cipher;
};

// Define a global variable with de ID for SHA-512 => ID_LENGTH = 19
unsigned char EMSASHA512ID[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
							 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 
							 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

unsigned char *
build_T(unsigned char *hash, int d){
	unsigned char *T;
	int i;
	
	// Allocate memory for T
	T = (unsigned char *)malloc(ID_LENGTH + SHA512_DIGEST_LENGTH);
	
	// ID||HASH
	memcpy(T, EMSASHA512ID, ID_LENGTH);
	memcpy(&T[ID_LENGTH], hash, SHA512_DIGEST_LENGTH);
	
	// If debug => print T
	if(d){
		printf("\nT: ");
		for(i = 0; i < (ID_LENGTH + SHA512_DIGEST_LENGTH); i++){
			// %02x prints at least 2 digists, prepend by 0 if there's less
			printf("%02x", T[i]);
		}
		printf("\n");
	}
	
	return T;
}

unsigned char *
build_PS(int d){
	unsigned char *PS;
	int i;
	
	// Allocate memory for PS
	PS = (unsigned char *)malloc(PS_LENGTH);
	
	// Fill PS with 0xFF byte value on its length
	memset(PS, 0xFF, PS_LENGTH);
	
	// If debug print PS
	if(d){
		printf("\nPS: ");
		for(i = 0; i < (3 + PS_LENGTH); i++){
			// %02x prints at least 2 digists, prepend by 0 if there's less
			printf("%02x", PS[i]);
		}
		printf("\n");
	}
	
	// Return PS
	return PS;
}

unsigned char *
build_message(unsigned char *hash, int d){
	unsigned char *message;
	unsigned char *T;
	unsigned char *PS;
	int i;
	
	// Allocate memory for the message
	message = (unsigned char *)malloc(3 + PS_LENGTH + SHA512_DIGEST_LENGTH + ID_LENGTH);
	
	// If debug
	if(d){
		printf("\nPS LEN: %d", PS_LENGTH);
		printf("\nSIGN LEN: %d", 3 + PS_LENGTH + SHA512_DIGEST_LENGTH + ID_LENGTH);
	}
	
	// Build T
	T = build_T(hash, d);
	
	// Build PS
	PS = build_PS(d);
	
	// Start building the message
	// 0x00||0x01||PS||0x00||T
	message[0] = 0x00;
	message[1] = 0x01;
	memcpy(&message[2], PS, PS_LENGTH);
	message[428] = 0x00;
	memcpy(&message[429], T, SHA512_DIGEST_LENGTH + ID_LENGTH);
	
	//printf("LEN: %d", 3 + PS_LENGTH + SHA512_DIGEST_LENGTH);
	// If debug => print message
	if(d){
		printf("\nMessage: ");
		for(i = 0; i < (3 + PS_LENGTH + SHA512_DIGEST_LENGTH + ID_LENGTH); i++){
			// %02x prints at least 2 digists, prepend by 0 if there's less
			printf("%02x", message[i]);
		}
		printf("\n");
	}
	
	
	// Free allocated memory for T building
	free(T);
	// Free allocated memory for PS building
	free(PS);
	
	// Return the built message
	return message;
}

unsigned char *
build_padding(int d){
	unsigned char *padding;
	unsigned char *PS;
	int i;
	
	// Allocate memory for the message						HACER FREE
	padding = (unsigned char *)malloc(PAD_LENGTH);
	
	// Build PS
	PS = build_PS(d);
	
	// Start building the padding
	// 0x00||0x01||PS||0x00||T
	padding[0] = 0x00;
	padding[1] = 0x01;
	memcpy(&padding[2], PS, PS_LENGTH);
	padding[428] = 0x00;
	memcpy(&padding[429], EMSASHA512ID, ID_LENGTH);
	
	// If debug => print padding
	if(d){
		printf("\nPadding: ");
		for(i = 0; i < (PAD_LENGTH); i++){
			// %02x prints at least 2 digists, prepend by 0 if there's less
			printf("%02x", padding[i]);
		}
		printf("\n");
	}
	
	// Free PS
	free(PS);
	
	return padding;
}

Signature *
cipher_message(char *privkeypath, unsigned char *message, int d){
	FILE *f;
	RSA *rsa;
	Signature *sig;
	int rsa_size;
	unsigned char *result;
	int sign_length;
	
	// Open private key file passed by arg
	f = fopen(privkeypath, "r");
	if(f == NULL){
		if(d)
			fprintf(stderr, "Error: fopen");
		exit(EXIT_FAILURE);
	}
	
	// Read the private key
	rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
	if(rsa == NULL){
		if(d)
			fprintf(stderr, "Error: PEM_read_RSAPrivateKey");
		exit(EXIT_FAILURE);
	}
	
	// Get rsa size
	rsa_size = RSA_size(rsa);

	if(d)
		printf("\n%d\n", rsa_size);
		
	// Allocate memory for result
	result = malloc(rsa_size);
	if(result == NULL){
		if(d)
			fprintf(stderr, "Error: malloc");
		exit(EXIT_FAILURE);
	}
	// Allocate memory for Signature structure
	sig = malloc(sizeof(Signature));
	if(sig == NULL){
		if(d)
			fprintf(stderr, "Error: malloc");
		exit(EXIT_FAILURE);
	}
	
	// Encrypt
	sign_length = RSA_private_encrypt(SIGN_LENGTH, message, result, rsa, RSA_NO_PADDING);
	if(sign_length < 0){
		if(d)
			fprintf(stderr, "Error: RSA_private_encrypt");
		exit(EXIT_FAILURE);
	}
	
	// Fill sig struct
	sig->len = sign_length;
	sig->cipher = result;
	
	RSA_free(rsa);
	fclose(f);
	return sig;
}

void
free_signature(Signature *sig){
	free(sig->cipher);
	free(sig);
}

Signature *
decipher_message(char *pubkeypath, unsigned char *cipher, int d){
	FILE *f;
	RSA *rsa;
	Signature *sig;
	int rsa_size;
	unsigned char *result;
	int sign_length;
	
	// Open private key file passed by arg
	f = fopen(pubkeypath, "r");
	if(f == NULL){
		if(d)
			fprintf(stderr, "Error: fopen");
		exit(EXIT_FAILURE);
	}
	
	// Read the pub key
	rsa = PEM_read_RSA_PUBKEY(f, NULL, NULL, NULL);
	if(rsa == NULL){
		if(d)
			fprintf(stderr, "Error: PEM_read_RSA_PUBKEY");
		exit(EXIT_FAILURE);
	}
	
	// Get rsa size
	rsa_size = RSA_size(rsa);

	if(d)
		printf("\n%d\n", rsa_size);
	
	// Allocate memory for result
	result = malloc(rsa_size);
	if(result == NULL){
		if(d)
			fprintf(stderr, "Error: malloc");
		exit(EXIT_FAILURE);
	}
	// Allocate memory for Signature structure
	sig = malloc(sizeof(Signature));
	if(sig == NULL){
		if(d)
			fprintf(stderr, "Error: malloc");
		exit(EXIT_FAILURE);
	}
	
	// Decrypt
	sign_length = RSA_public_decrypt(SIGN_LENGTH, cipher, result, rsa, RSA_NO_PADDING);
	if(sign_length < 0){
		if(d)
			fprintf(stderr, "Error: RSA_private_encrypt");
		exit(EXIT_FAILURE);
	}
	
	// Fill sig struct
	sig->len = sign_length;
	sig->cipher = result;
	
	RSA_free(rsa);
	fclose(f);
	return sig;
}

void
b64_encode(Signature *sig){
	BIO *b64;
	BIO *bio;
	
	// Init BIO Structure
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_push(b64, bio);
	
	// Print message on b64
	printf("%s\n", "---BEGIN SRO SIGNATURE---");
	BIO_write(b64, sig->cipher, sig->len);
	
	// Free memory
	BIO_flush(b64);
	BIO_free_all(b64);
	printf("%s\n", "---END SRO SIGNATURE---");
}

unsigned char *
b64_decode(char *signfile, int d){
	FILE *f;
	BIO *b64;
	BIO *bio;
	int n;
	int nr = 0;
	unsigned char *buf;
	int i;
	
	// Allocate memory for buf
	buf = (unsigned char *)malloc(SIGN_LENGTH);
	
	// Open file and check if there is an error
	f = fopen(signfile, "r");
	if(f == NULL){
		if(d)
			fprintf(stderr, "Error: fopen");
		exit(EXIT_FAILURE);
	}
	
	// Init BIO Structure
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(f, BIO_NOCLOSE);
	BIO_push(b64, bio);
	
	// Print message on b64
	for(;;){
		n = BIO_read(b64, buf, SIGN_LENGTH-nr);
		if(n == 0){
			// Free memory
			BIO_free_all(b64);
			// Close fd
			fclose(f);
			break;
		}else if(n < 0){
			if(d)
				fprintf(stderr, "Error: BIO_read");
			exit(EXIT_FAILURE);
		}
		nr += n;
	}
	
	// If debug => print message
	if(d){
		printf("\nCipher: ");
		for(i = 0; i < (SIGN_LENGTH); i++){
			// %02x prints at least 2 digists, prepend by 0 if there's less
			printf("%02x", buf[i]);
		}
		printf("\n");
	}
	
	return buf;
}

unsigned char *
sha512(char *path, int d){
	FILE *f;
	size_t n;
	char buffer[MAXBUFF];
	SHA512_CTX c;
	unsigned char *md;
	int i;

	// Open file and check if there is an error
	f = fopen(path, "r");
	if(f == NULL){
		if(d)
			fprintf(stderr, "Error: fopen\n");
		exit(EXIT_FAILURE);
	}
	
	// Init SHA512_CTX Structure
	if(SHA512_Init(&c) == 0){
		if(d)
			fprintf(stderr, "Error: SHA512_INIT\n");
		exit(EXIT_FAILURE);
	}
	
	// Read the file char by char
	while((n = fread(buffer, sizeof(char), 1, f))!=0){
		// Update SHA512
		if(SHA512_Update(&c, buffer, n) == 0){
			if(d)
				fprintf(stderr, "Error: SHA512 Update\n");
			exit(EXIT_FAILURE);
		}
	}
	
	// Update with the file name => data + filename
	if (SHA512_Update(&c, path, strlen(path)) != 1){
		if (d) 
			fprintf(stderr, "Error: SHA512_Update\n");
		exit(EXIT_FAILURE);
	}
	
	// Allocate memory for hash
	md = (unsigned char *)malloc(SHA512_DIGEST_LENGTH);
	
	// Finalize SHA512 => HASH(data + filename)
	if(SHA512_Final(md, &c) == 0){
		if(d)
			fprintf(stderr, "Error: SHA512 Final\n");
		exit(EXIT_FAILURE);
	}
	
	// If debug => print SHA512
	if(d){
		printf("\nHASH: ");
		for(i = 0; i < SHA512_DIGEST_LENGTH; i++){
			// %02x prints at least 2 digists, prepend by 0 if there's less
			printf("%02x", md[i]);
		}
		printf("\n");
	}
	// Close f
	fclose(f);
	// Return HASH
	return md;
}

void
check_padding(unsigned char *padding, Signature *sig, int d){
	int i;
	
	if(d){
		printf("PAD LEN: %d", PAD_LENGTH);
		printf("\nCIPHER: ");
		for(i = 0; i < PAD_LENGTH; i++){
			// %02x prints at least 2 digists, prepend by 0 if there's less
			printf("%02x", sig->cipher[i]);
		}
		printf("\n");
	}
	
	if (memcmp(padding, sig->cipher, PAD_LENGTH) != 0){
		if (d) 
			fprintf(stderr, "Error: wrong padding\n");
		fprintf(stderr, "Invalid signature: signature does not match file\n");
		exit(EXIT_FAILURE);
	}
}

void
check_sha512(char *datafile, Signature *sig, int d){
	unsigned char *sha;
	sha = sha512(datafile, d);
	if (memcmp(sha, &sig->cipher[PAD_LENGTH], SHA512_DIGEST_LENGTH) != 0){
		fprintf(stderr, "Invalid signature: signature does not match file\n");
		exit(EXIT_FAILURE);
	}
	free(sha);
}

void
handle_args(int argc, char *argv[], int *v, int *d, char **datafile, char **keyfile, char **signfile){
	char d_flag[2] = "-d";
	char v_flag[2] = "-v";
	
	// Error if there is more arguments or less than our program contemplates
	if(argc < 2 || argc > 5){
		if(*d)
			fprintf(stderr, "Usage: sign [-d] [-v signfile] datafile keyfile\n");
		exit(EXIT_FAILURE);
	}
	
	// If there is 2-5 arguments, continue parsing them
	//		If there is 2 args => sign datafile keyfile
	if(argc == 2){
		if(*d)
			printf("DOS argumentos detectados\n");
		*datafile = argv[0];
		*keyfile = argv[1];
		return;
	}
	//		If there is 3 arguments => sign -d datafile keyfile
	if(argc == 3){
		if(*d)
			printf("TRES argumentos detectados\n");
		// Check that flag is d_flag
		if(strncmp(argv[0], d_flag, 2) != 0){
			if(*d)
				fprintf(stderr, "Usage: sign [-d] [-v signfile] datafile keyfile\n");
			exit(EXIT_FAILURE);
		}
		
		*d = 1;
		*datafile = argv[1];
		*keyfile = argv[2];
		return;
	}
	//		If there is 4 arguments => sign -v signfile datafile keyfile
	if(argc == 4){
		if(*d)
			printf("CUATRO argumentos detectados\n");
		// Check that flag is v_flag
		if(strncmp(argv[0], v_flag, 2) != 0){
			if(*d)
				fprintf(stderr, "Usage: sign [-d] [-v signfile] datafile keyfile\n");
			exit(EXIT_FAILURE);
		}
		
		*v = 1;
		*signfile = argv[1];
		*datafile = argv[2];
		*keyfile = argv[3];
		return;
	}
	// 		If there is 5 arguments => sign -d -v signfile datafile keyfile
	if(argc == 5){
		if(*d)
			printf("CUATRO argumentos detectados\n");
		// Check that first flag is d_flag
		if(strncmp(argv[0], d_flag, 2) != 0){
			if(*d)
				fprintf(stderr, "Usage: sign [-d] [-v signfile] datafile keyfile\n");
			exit(EXIT_FAILURE);
		}
		// Check that second flag is v flag
		if(strncmp(argv[1], v_flag, 2) != 0){
			if(*d)
				fprintf(stderr, "Usage: sign [-d] [-v signfile] datafile keyfile\n");
			exit(EXIT_FAILURE);
		}
		
		*d = 1;
		*v = 1;
		*signfile = argv[2];
		*datafile = argv[3];
		*keyfile = argv[4];
		return;
	}
}

int
main(int argc, char *argv[]){
	int v = 0;				// -v flag
	int debug = 0;			// -d flag
	char *datafile;			// Data file to sign
	char *keyfile;			// RSA Key
	char *signfile;			// File with the digital signature
	unsigned char *hash;	// HASH(data + filename)
	unsigned char *message; // M = 0x00||0x01||PS||0x00||T
	Signature *sig;			// Struct that stores signature and len
	unsigned char *cipher;	
	unsigned char *padding;
	
	// Argument handling
	argc--;
	argv++;
	handle_args(argc, argv, &v, &debug, &datafile, &keyfile, &signfile);
	// If debug, print data
	if(debug)
		printf("\n-d: %d\n-v: %d\nsignfile: %s\ndatafile: %s\nkeyfile: %s\n",
			debug, v, signfile, datafile, keyfile);
			
	// If not -v, don't verify signature
	// => sign file
	// Sign format: RSASSA-PKCS1 V1.5. Key: 4096bits and SHA-512
	if(!v){
		// Get the datafile HASH 				HACER FREE AL FINAL
		hash = sha512(datafile, debug);
		
		// Build the message => M = 0x00||0x01||PS||0x00||T
		// T = ID || HASH
		// PS = (4096/8)−len(T)−3
		message = build_message(hash, debug);
		
		// Cipher message
		sig = cipher_message(keyfile, message, debug);
		
		// Encode the msg on base64
		b64_encode(sig);
		
		// Free message
		free(message);
		// Free memory from hash variable used to store HASH(data+filename)
		free(hash);
	}else{
		// If -v => verify signature
		// 	Decode b64
		cipher = b64_decode(signfile, debug);
		
		// Decipher 
		sig = decipher_message(keyfile, cipher, debug);
		
		// Build padding
		padding = build_padding(debug);
		
		// Compare between paddings, the one deciphered and the one built
		check_padding(padding, sig, debug);
		
		// Check SHA-512
		check_sha512(datafile, sig, debug);
		
		// Free memory
		free(cipher);
	}
	// Free signature structure
	free_signature(sig);
}
