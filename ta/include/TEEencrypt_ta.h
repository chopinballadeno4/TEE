#ifndef TA_TEEencrypt_H
#define TA_TEEencrypt_H
#define TA_TEEencrypt_UUID \
	{ 0x38de8f21 ,0x5c50, 0x4d7e, \
		{ 0xa4, 0xe5, 0x4b, 0x1d, 0xad, 0x38, 0xa8, 0x9d} }

/* The function IDs implemented in this TA */
#define TA_TEEencrypt_CMD_CREATE_RANDOMKEY	0
#define TA_TEEencrypt_CMD_ENC_RANDOMKEY		1
#define TA_TEEencrypt_CMD_DEC_RANDOMKEY		2
#define TA_TEEencrypt_CMD_ENC_VALUE		3
#define TA_TEEencrypt_CMD_DEC_VALUE		4
#endif
