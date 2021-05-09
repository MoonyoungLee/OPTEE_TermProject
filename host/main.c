#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	int opt;
	extern char *optarg;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;
	FILE *plainfp, *cipherfp, *rkfp;
	char cbuffer[20]; // ciphtertext buffer
	int key; // encrypted randomkey

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	while((opt=getopt(argc, argv,"e:d:")) != -1 )
	{
		switch(opt)
		{
		case 'e': //option 'e' is encryption textfile
			// TODO 1-1: open plaintext
			plainfp = fopen(optarg, "r");
			if(plainfp == NULL){
				printf("There is no file.\n");			
			}else{
				// TODO 1-2: read plaintext
				fgets(plaintext, sizeof(plaintext), plainfp); 
				printf("%s", plaintext);
			}
			// TODO 1-3: send plaintext
			memcpy(op.params[0].tmpref.buffer, plaintext, len);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_PLAINTEXT_CAESAR, &op,
				 &err_origin); 
			// TODO 4: receive randomkey_enc, ciphertext from TA
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			printf("Ciphertext : %s", ciphertext);
			printf("TEEencryption is done\n");
			// TODO 5: save ciphertext.txt in root directory
			cipherfp = fopen("ciphertext.txt", "w");
			fputs(ciphertext, cipherfp);
			fclose(cipherfp);

			rkfp = fopen("randomkey.txt", "w");
			int tmp = op.params[1].value.a;
			fprintf(rkfp, "%d",tmp);
			fclose(rkfp);
			break;
		case 'd': // option 'd' is decryption textfile
			// TODO 6-1: open ciphtertext file
			cipherfp = fopen(optarg, "r");
			// TODO 6-2: read ciphertext file
			fgets(cbuffer, sizeof(cbuffer), cipherfp);
			printf("ciphertext: %s", cbuffer);
			// TODO 6-3:close ciphertext file
			fclose(cipherfp);

			// TODO 7-1: open randomkey file
			rkfp = fopen(argv[3],"r");
			// TODO 7-2: read randomkey
			fscanf(rkfp, "%d", &key);
			// TODO 7-3: close randomkey file
			fclose(rkfp);
			// TODO 8: send ciphertext, encrypted randomkey to TA
			// copy ciphertext, encrypted randomkey to op buffer
			memcpy(op.params[0].tmpref.buffer, cbuffer, len);
			op.params[1].value.a = key;
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_CIPERTEXT_CAESAR, &op,
				 &err_origin); 
			// TODO 11: receive plaintext from TA
			memcpy(plaintext, op.params[0].tmpref.buffer, len);
			printf("Plaintext : %s", plaintext);
			printf("TEEdecryption is done\n");
			// TODO 12: write plaintext in original.txt
			plainfp = fopen("original.txt", "w");
			fputs(plaintext, plainfp);
			fclose(plainfp);
			break;
		default : printf("no option [%c]\n", opt); break;
		}  
	}

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
