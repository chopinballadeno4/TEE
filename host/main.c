#include <err.h>
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include <TEEencrypt_ta.h>

#include <fcntl.h> 
#include <unistd.h>

#define CAESAR_ENCRYPT 0
#define CAESAR_DECRYPT 1

int main(int argc, char** argv)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	
	uint32_t err_origin;

	char plaintext[1024] = {0,};
	char ciphertext[1024] = {0,};
	char random_key[3];
	int len = 1024;
	int file_num;


	if(argc > 4){
		printf("!!! too many inputs.\n");
		return 1;
	} else if(argc <= 2) {
		printf("!!! not enough input.\n");
		return 1;
	}

	if(strcmp(argv[1], "-e") == 0) {
		res = TEEC_InitializeContext(NULL, &ctx); 
		if (res != TEEC_SUCCESS) {
			errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
		}

		res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		if (res != TEEC_SUCCESS) {
			errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",res, err_origin);
		}

		file_num = open(argv[2], O_RDONLY);
		if(file_num == -1) {
			printf("!!! failed to read file.");
			return 1;
		} else {
			read(file_num, plaintext, len);
			close(file_num);
		}

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
		memcpy(op.params[0].tmpref.buffer, plaintext, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_CREATE_RANDOMKEY, &op, &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_RANDOMKEY, &op, &err_origin);

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);

		random_key[0] = op.params[1].value.a;
		random_key[1] = '\0';
		strcat(ciphertext, random_key);

		file_num = creat("./ciphertext.txt", 0644);
		if( file_num > 0) {
			write(file_num, ciphertext, strlen(ciphertext));
			close(file_num);
		} else {
			printf("!!! failed to write file.");
			return 1;
		}
		
		printf("Encryption complete!\n");

		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
	} else if(strcmp(argv[1], "-d") == 0) {
		res = TEEC_InitializeContext(NULL, &ctx);
		if (res != TEEC_SUCCESS) {
			errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
		}

		res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		if (res != TEEC_SUCCESS) {
			errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
		}

		file_num = open(argv[2], O_RDONLY);
		if(file_num == -1){
			printf("!!! failed to read file.");
			return 1;
		} else {
			read(file_num, ciphertext, len);
			close(file_num);
		}

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = len;
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_RANDOMKEY, &op, &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		
		file_num = creat("./plaintext.txt", 0644);
		if( file_num > 0){
			write(file_num, plaintext, strlen(plaintext));
			close(file_num);
		} else {
			printf("!!! failed to write file.");
			return 1;
		}

		printf("Decryption complete!\n");

		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
	} else {
		printf("!!! Wrong option.\n");
	}

	return 0;
}

