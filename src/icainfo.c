/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Display a list of all CP Assist for Cryptographic Function (CPACF)
 * operations supported by libica on a system.
 *
 * Author(s): Ralph Wuerthner <rwuerthn@de.ibm.com>
 * 	      Holger Dengler <hd@linux.vnet.ibm.com>
 * 	      Benedikt Klotz <benedikt.klotz@de.ibm.com>
 * 	      Ingo Tuchscherer <ingo.tuchscherer@de.ibm.com>
 *
 * Copyright IBM Corp. 2007, 2011, 2014
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "fips.h"
#include "ica_api.h"
#include "s390_crypto.h"

#if defined(NO_SW_FALLBACKS) && defined(NO_CPACF)
#define CMD_NAME "icainfo-cex"
#else
#define CMD_NAME "icainfo"
#endif
#define COPYRIGHT "Copyright IBM Corp. 2007, 2021."


void print_version(void)
{
#if defined(NO_SW_FALLBACKS) && defined(NO_CPACF)
	printf(CMD_NAME ": libica-cex version " VERSION "\n" COPYRIGHT "\n");
#else
	printf(CMD_NAME ": libica version " VERSION "\n" COPYRIGHT "\n");
#endif
}

void print_help(char *cmd)
{
	printf("Usage: %s [OPTION]\n", cmd);
	printf
	    ("Display a list of all CP Assist for Cryptographic Function "
	     "(CPACF)\noperations supported by libica on this system.\n"
	     "\n" "Options:\n"
	     " -v, --version  show version information\n"
	     " -h, --help     display this help text\n");
}

#define getopt_string "qvh"
static struct option getopt_long_options[] = {
	{"version", 0, 0, 'v'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};


struct crypt_pair {
	char *name;
	unsigned int algo_id;
};

static struct crypt_pair crypt_map[] = {
	{"SHA-1", SHA1},
	{"SHA-224", SHA224},
	{"SHA-256", SHA256},
	{"SHA-384", SHA384},
	{"SHA-512", SHA512},
	{"SHA-512/224", SHA512_224},
	{"SHA-512/256", SHA512_256},
	{"SHA3-224", SHA3_224},
	{"SHA3-256", SHA3_256},
	{"SHA3-384", SHA3_384},
	{"SHA3-512", SHA3_512},
	{"SHAKE-128", SHAKE128},
	{"SHAKE-256", SHAKE128},
	{"GHASH", G_HASH},
	{"P_RNG", P_RNG},
	{"DRBG-SHA-512", SHA512_DRNG},
	{"ECDH", EC_DH},
	{"ECDSA Sign", EC_DSA_SIGN},
	{"ECDSA Verify", EC_DSA_VERIFY},
	{"EC Keygen", EC_KGEN},
	{"Ed25519 Keygen", ED25519_KEYGEN},
	{"Ed25519 Sign", ED25519_SIGN},
	{"Ed25519 Verify", ED25519_VERIFY},
	{"Ed448 Keygen", ED448_KEYGEN},
	{"Ed448 Sign", ED448_SIGN},
	{"Ed448 Verify", ED448_VERIFY},
	{"X25519 Keygen", X25519_KEYGEN},
	{"X25519 Derive", X25519_DERIVE},
	{"X448 Keygen", X448_KEYGEN},
	{"X448 Derive", X448_DERIVE},
	{"RSA ME", RSA_ME},
	{"RSA CRT", RSA_CRT},
	{"DES ECB", DES_ECB},
	{"DES CBC", DES_CBC},
	{"DES OFB", DES_OFB},
	{"DES CFB", DES_CFB},
	{"DES CTR", DES_CTR},
	{"DES CMAC", DES_CMAC},
	{"3DES ECB", DES3_ECB},
	{"3DES CBC", DES3_CBC},
	{"3DES OFB", DES3_OFB},
	{"3DES CFB", DES3_OFB},
	{"3DES CTR", DES3_CTR},
	{"3DES CMAC", DES3_CMAC},
	{"AES ECB", AES_ECB},
	{"AES CBC", AES_CBC},
	{"AES OFB", AES_OFB},
	{"AES CFB", AES_CFB},
	{"AES CTR", AES_CTR},
	{"AES CMAC", AES_CMAC},
	{"AES XTS", AES_XTS},
	{"AES GCM", AES_GCM_KMA},
	{NULL,0}
};


int main(int argc, char **argv)
{
	int rc;
	int index = 0;
	unsigned int mech_len, j;
	libica_func_list_element *pmech_list = NULL;
	unsigned int i;

	while ((rc = getopt_long(argc, argv, getopt_string,
				 getopt_long_options, &index)) != -1) {
		switch (rc) {
		case 'v':
			print_version();
			exit(0);
			break;
		case 'h':
			print_help(basename(argv[0]));
			exit(0);
		default:
			fprintf(stderr, "Try '%s --help' for more"
				" information.\n", basename(argv[0]));
			exit(1);
		}
	}
	if (optind < argc) {
		fprintf(stderr, "%s: invalid option.\n"
			"Try '%s --help' for more information.\n",
			argv[0], basename(argv[0]));
		exit(1);
	}

	printf("              Cryptographic algorithm support      \n");
	printf("------------------------------------------------------\n");

	if (ica_get_functionlist(NULL, &mech_len) != 0){
		perror("get_functionlist: ");
		return EXIT_FAILURE;
	}
	pmech_list = malloc(sizeof(libica_func_list_element)*mech_len);
	if (ica_get_functionlist(pmech_list, &mech_len) != 0){
		perror("get_functionlist: ");
		free(pmech_list);
		return EXIT_FAILURE;
	}

	#define CELL_SIZE 3

	printf("               |         hardware        |            \n");
	printf(" function      |   dynamic  |   static   |  software  \n");
	printf("---------------+------------+------------+------------\n");
	for(i = 0; crypt_map[i].algo_id; i++){
		for(j = 0; j < mech_len; j++){
			if(crypt_map[i].algo_id == pmech_list[j].mech_mode_id){
#ifdef ICA_FIPS
				if (((ica_fips_status() & ICA_FIPS_MODE)
				    && !fips_approved(pmech_list[j].mech_mode_id))
				    || ica_fips_status() >> 1) {
#if defined(NO_SW_FALLBACKS) && defined(NO_CPACF)
					printf("%14s |  blocked   |      -     |      -   \n",
#elif defined (NO_CPACF)
					printf("%14s |  blocked   |      -     |      -   \n",
#elif defined (NO_SW_FALLBACKS)
					printf("%14s |  blocked   |   blocked  |      -   \n",
#else
					printf("%14s |  blocked   |   blocked  |   blocked\n",
#endif
						crypt_map[i].name);
					break;
				}
#endif /* ICA_FIPS */
				printf("%14s |    %*s     |    %*s     |    %*s\n",
					crypt_map[i].name,
					CELL_SIZE,
					pmech_list[j].flags & ICA_FLAG_DHW ? "yes" : "no",
					CELL_SIZE,
#ifdef NO_CPACF
					pmech_list[j].flags & ICA_FLAG_SHW ? "yes" : "-",
#else
					pmech_list[j].flags & ICA_FLAG_SHW ? "yes" : "no",
#endif
					CELL_SIZE,
#if defined(NO_SW_FALLBACKS) || defined(NO_CPACF)
					pmech_list[j].flags & ICA_FLAG_SW ? "yes" : "-");
#else
					pmech_list[j].flags & ICA_FLAG_SW ? "yes" : "no");
#endif
			}
		}
	}
	free(pmech_list);
	printf("------------------------------------------------------\n");

#ifdef ICA_FIPS
	printf("Built-in FIPS support: FIPS mode %s.\n",
	    ica_fips_status() & ICA_FIPS_MODE ? "active" : "inactive");
	if (ica_fips_status() >> 1)
		printf("FIPS SELF-TEST FAILURE. CHECK THE SYSLOG.\n");
#else
	printf("No built-in FIPS support.\n");
#endif /* ICA_FIPS */

#ifdef NO_SW_FALLBACKS
	printf("Software fallbacks are disabled in libica-cex.\n");
#endif
#ifdef NO_CPACF
	printf("CPACF support (including fallbacks) is disabled in libica-cex.\n");
#endif

	return EXIT_SUCCESS;
}
