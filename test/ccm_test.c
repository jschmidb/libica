/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2011 */

#include <fcntl.h>
#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ica_api.h"
#include "testcase.h"

#define BYTE 8

#define NUM_CCM_TESTS 4
unsigned char input_data[1000000];
unsigned char parameter_block[32];
unsigned char *to = parameter_block;

unsigned int key_length[4] = {16, 16, 16, 16};
unsigned char key[4][16] = {
{0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f },
{0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f },
{0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f },
{0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f }};

#define CASE3_ASSOC_LEN 256
/* Number of bytes in string for case 3 */

unsigned int assoc_data_length[4] = {8, 16, 20, 65536};
unsigned char assoc_data[4][65536] = {
{ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07 },
{ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f },
{ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13 }};
unsigned int i = 0;
unsigned char repeated_string[256] = {
0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,
0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,
0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,
0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,
0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,
0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
unsigned int payload_length[4] = {4, 16, 24, 32};
unsigned char payload[4][32] = {
{ 0x20,0x21,0x22,0x23 },
{ 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f},
{ 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37 },
{ 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f ,
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f }};

unsigned char payload_after_decrypt[4][32] = {
{ 0x20,0x21,0x22,0x23 },
{ 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f},
{ 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37 },
{ 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f ,
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f }};
unsigned int nonce_length[4] = {7,8,12,13};
unsigned char nonce[4][13] = {
{ 0x10,0x11,0x12,0x13,0x14,0x15,0x16},
{ 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17},
{ 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b},
{ 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c}};

unsigned int cbc_mac_length[4] = {4, 6, 8, 14};

unsigned int cipher_text_length[4] = {8, 22, 32, 46};
unsigned char cipher_text[4][46] = {
{ 0x71,0x62,0x01,0x5b,0x4d,0xac,0x25,0x5d },
{ 0xd2,0xa1,0xf0,0xe0,0x51,0xea,0x5f,0x62,0x08,0x1a,0x77,0x92,0x07,0x3d,0x59,0x3d,
  0x1f,0xc6,0x4f,0xbf,0xac,0xcd },
{ 0xe3,0xb2,0x01,0xa9,0xf5,0xb7,0x1a,0x7a,0x9b,0x1c,0xea,0xec,0xcd,0x97,0xe7,0x0b,
  0x61,0x76,0xaa,0xd9,0xa4,0x42,0x8a,0xa5,0x48,0x43,0x92,0xfb,0xc1,0xb0,0x99,0x51},
{0x69,0x91,0x5d,0xad,0x1e,0x84,0xc6,0x37,0x6a,0x68,0xc2,0x96,0x7e,0x4d,0xab,0x61,
 0x5a,0xe0,0xfd,0x1f,0xae,0xc4,0x4c,0xc4,0x84,0x82,0x85,0x29,0x46,0x3c,0xcf,0x72,
 0xb4,0xac,0x6b,0xec,0x93,0xe8,0x59,0x8e,0x7f,0x0d,0xad,0xbc,0xea,0x5b}
};

int api_ccm_test(void)
{
	unsigned char *out_data;
	int rc = 0;

	VV_(printf("Test of CCM api\n"));
	while ( i < 65536 ) { // init big assoc_data
		memcpy(assoc_data[3] + i, repeated_string, 256);
		i= i + 256;
	}
	for (i = 0; i < NUM_CCM_TESTS; i++) {
		VV_(printf("\nOriginal data for test %d:\n", i));
		if (!(out_data = malloc(cipher_text_length[i])))
			return TEST_ERR;
		memset(out_data, 0, cipher_text_length[i]);
		rc = (ica_aes_ccm(payload[i], payload_length[i],
				  out_data,
				  cbc_mac_length[i],
				  assoc_data[i], assoc_data_length[i],
				  nonce[i], nonce_length[i],
				  key[i], key_length[i],
				  ICA_ENCRYPT));
		if (rc) {
			VV_(printf("icaccm encrypt failed with errno %d (0x%x).\n",
				 rc, rc));
			return TEST_FAIL;
		}
		VV_(printf("\nOutput Cipher text for test %d:\n", i));
		dump_array(out_data, cipher_text_length[i]);
		VV_(printf("\nExpected Cipher Text for test %d:\n", i));
		dump_array(cipher_text[i], cipher_text_length[i]);

		if (memcmp(cipher_text[i], out_data, cipher_text_length[i]) != 0) {
			printf("This does NOT match the known result.\n");
			return TEST_FAIL;
		}

		VV_(printf("Yep, that's how it should be encrypted.\n"));
		// start decrypt / verify
		memset(payload[i], 0, payload_length[i]);
		rc = (ica_aes_ccm(out_data, payload_length[i],
				  cipher_text[i], cbc_mac_length[i],
				  assoc_data[i], assoc_data_length[i],
				  nonce[i], nonce_length[i],
				  key[i], key_length[i],
				  ICA_DECRYPT));
		if (rc) {
			VV_(printf("icaccm decrypt failed with errno %d (0x%x).\n",
				rc,rc));
			return TEST_FAIL;
		}

		VV_(printf("\nOutput payload for test %d:\n", i));
		dump_array(out_data, payload_length[i]);
		VV_(printf("\nExpected payload for test %d:\n", i));
		dump_array(payload_after_decrypt[i], payload_length[i]);

		if (memcmp(out_data, payload_after_decrypt[i],
				payload_length[i]) == 0 ) {
			VV_(printf("Yep, payload matches to original.\n"));
		} else {
			VV_(printf("This does NOT match the known result.\n"));
			return TEST_FAIL;
		}
		free(out_data);
	}

	return TEST_SUCC;
}

int main(int argc, char **argv)
{
#ifdef NO_CPACF
	UNUSED(argc);
	UNUSED(argv);
	printf("Skipping AES-CCM test, because CPACF support disabled via config option.\n");
	return TEST_SKIP;
#else
	int rc = 0;

	set_verbosity(argc, argv);

	rc = api_ccm_test();
	if (rc) {
		printf("api_ccm_test failed with rc = %i.\n", rc);
		return TEST_FAIL;
	}

	printf("All AES-CCM tests passed.\n");
	return TEST_SUCC;
#endif /* NO_CPACF */
}


