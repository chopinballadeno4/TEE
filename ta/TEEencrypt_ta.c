#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>
#include <stdio.h>
#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

struct rsa_session {
	TEE_OperationHandle op_handle;	
	TEE_ObjectHandle key_handle; 
};

int root_key=9;
unsigned int random_key;


TEE_Result TA_CreateEntryPoint(void) {
	DMSG("CreateEntryPoint has been called");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
	DMSG("DestroyEntryPoint has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param __maybe_unused params[4], void __maybe_unused **sess_ctx) {
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	DMSG("OpenSessionEntryPoint has been called");

	if (param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;
	*sess_ctx = (void *)sess;

	IMSG("Hello World!\n");

	return TEE_SUCCESS;
}


void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx) {
	(void)&sess_ctx; 
	IMSG("Goodbye!\n");
}


static TEE_Result create_randomkey(uint32_t param_types, TEE_Param params[4]) {
	DMSG("========================Create Random Key========================\n");
	TEE_GenerateRandom(&random_key, sizeof(random_key));
	random_key = random_key % 26;

	while(random_key == 0) {
		TEE_GenerateRandom(&random_key, sizeof(random_key));
		random_key = random_key % 26;
	}
	
	IMSG("Created RandomKey: %d\n", random_key);

	return TEE_SUCCESS;
}
	
static TEE_Result enc_randomkey(uint32_t param_types, TEE_Param params[4]) {
	DMSG("========================Random Key(enc)========================\n");

	if(random_key>='a' && random_key <='z'){
		random_key -= 'a';
		random_key += root_key;
		random_key = random_key % 26;
		random_key += 'a';
	} else if (random_key >= 'A' && random_key <= 'Z') {
		random_key -= 'A';
		random_key += root_key;
		random_key = random_key % 26;
		random_key += 'A';
	}
	params[1].value.a = (uint32_t)random_key;

	return TEE_SUCCESS;
}

static TEE_Result dec_randomkey(uint32_t param_types, TEE_Param params[4]) {
	char * var = (char *)params[0].memref.buffer;
	int var_len = strlen (params[0].memref.buffer);
	char enc_arr [1024]={0,};	
	
	DMSG("========================Random Key(dec)========================\n");
	memcpy(enc_arr, var, var_len);
	random_key = enc_arr[var_len-1];

	if(random_key>='a' && random_key <='z') {
		random_key -= 'a';
		random_key -= root_key;
		random_key += 26;
		random_key = random_key % 26;
		random_key += 'a';
	} else if (random_key >= 'A' && random_key <= 'Z') {
		random_key -= 'A';
		random_key -= root_key;
		random_key += 26;
		random_key = random_key % 26;
		random_key += 'A';
	}
	IMSG("Got value: %c from NW\n", enc_arr[var_len-1]);
	IMSG("Decrypted RandomKey: %d\n", random_key);

	return TEE_SUCCESS;
}

static TEE_Result enc_value(uint32_t param_types, TEE_Param params[4]) {
	DMSG("enc_value has been called");

	char * var = (char *)params[0].memref.buffer;
	int var_len = strlen (params[0].memref.buffer);
	char enc_arr [1024]={0,};

	DMSG("========================Encryption Value========================\n");
	DMSG ("Plaintext:  %s", var);
	memcpy(enc_arr, var, var_len);

	for(int i=0; i<var_len; i++){
		if(enc_arr[i]>='a' && enc_arr[i] <='z'){
			enc_arr[i] -= 'a';
			enc_arr[i] += random_key;
			enc_arr[i] = enc_arr[i] % 26;
			enc_arr[i] += 'a';
		} else if (enc_arr[i] >= 'A' && enc_arr[i] <= 'Z') {
			enc_arr[i] -= 'A';
			enc_arr[i] += random_key;
			enc_arr[i] = enc_arr[i] % 26;
			enc_arr[i] += 'A';
		}
	}
	memcpy(var, enc_arr, var_len);
	DMSG ("Ciphertext:  %s", enc_arr);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types, TEE_Param params[4]) {
	DMSG("dec_value has been called");

	char * var = (char *)params[0].memref.buffer;
	int var_len = strlen (params[0].memref.buffer);
	char dec_arr [1024]={0,};
	
	DMSG("========================Decryption========================\n");
	DMSG ("Ciphertext:  %s", var);
	memcpy(dec_arr, var, var_len);

	for(int i=0; i<var_len-1; i++){
		if(dec_arr[i]>='a' && dec_arr[i] <='z'){
			dec_arr[i] -= 'a';
			dec_arr[i] -= random_key;
			dec_arr[i] += 26;
			dec_arr[i] = dec_arr[i] % 26;
			dec_arr[i] += 'a';
		} else if (dec_arr[i] >= 'A' && dec_arr[i] <= 'Z') {
			dec_arr[i] -= 'A';
			dec_arr[i] -= random_key;
			dec_arr[i] += 26;
			dec_arr[i] = dec_arr[i] % 26;
			dec_arr[i] += 'A';
		}
	}
	dec_arr[var_len-1] = '\0';
	DMSG ("Plaintext:  %s", dec_arr);
	memcpy(var, dec_arr, var_len);

	return TEE_SUCCESS;	
}


TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4]) {
	//(void)&sess_ctx; 
	switch (cmd_id) {
	case TA_TEEencrypt_CMD_CREATE_RANDOMKEY:
		return create_randomkey(param_types, params);
	case TA_TEEencrypt_CMD_ENC_RANDOMKEY:
		return enc_randomkey(param_types, params);
	case TA_TEEencrypt_CMD_DEC_RANDOMKEY:
		return dec_randomkey(param_types, params);
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
}
}
