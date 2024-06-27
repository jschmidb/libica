/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

#ifndef S390_MLDSA_H
#define S390_MLDSA_H

#include <asm/zcrypt.h>
#include "s390_cca.h"
#include "ica_api.h"


extern unsigned int mldsa_via_online_card;

#define _MAX(a, b)  ((a) > (b) ? (a) : (b))

/* QSA Public Key components */
#define DILITHIUM_3_65_RHO_SIZE         32
#define DILITHIUM_3_87_RHO_SIZE         32

#define DILITHIUM_3_65_T1_SIZE          1920
#define DILITHIUM_3_87_T1_SIZE          2560

#define DILITHIUM_3_65_PUBKEY_SIZE      (DILITHIUM_3_65_RHO_SIZE \
                                       + DILITHIUM_3_65_T1_SIZE)
#define DILITHIUM_3_87_PUBKEY_SIZE      (DILITHIUM_3_87_RHO_SIZE \
                                       + DILITHIUM_3_87_T1_SIZE)

#define MAX_MLDSA_PUBKEY_SIZE           _MAX(DILITHIUM_3_65_PUBKEY_SIZE, \
                                             DILITHIUM_3_87_PUBKEY_SIZE)

/* QSA Private Key components */
#define DILITHIUM_3_65_SEED_SIZE        32
#define DILITHIUM_3_87_SEED_SIZE        32

#define DILITHIUM_3_65_TR_SIZE          32
#define DILITHIUM_3_87_TR_SIZE          32

#define DILITHIUM_3_65_S1_SIZE          640
#define DILITHIUM_3_87_S1_SIZE          672

#define DILITHIUM_3_65_S2_SIZE          768
#define DILITHIUM_3_87_S2_SIZE          768

#define DILITHIUM_3_65_T0_SIZE          2496
#define DILITHIUM_3_87_T0_SIZE          3328

#define DILITHIUM_3_65_PRIVKEY_SIZE      (DILITHIUM_3_65_SEED_SIZE  \
                                        + DILITHIUM_3_65_TR_SIZE    \
                                        + DILITHIUM_3_65_S1_SIZE    \
                                        + DILITHIUM_3_65_S2_SIZE    \
                                        + DILITHIUM_3_65_T0_SIZE)

#define DILITHIUM_3_87_PRIVKEY_SIZE      (DILITHIUM_3_87_SEED_SIZE  \
                                        + DILITHIUM_3_87_TR_SIZE    \
                                        + DILITHIUM_3_87_S1_SIZE    \
                                        + DILITHIUM_3_87_S2_SIZE    \
                                        + DILITHIUM_3_87_T0_SIZE)

#define MAX_MLDSA_PRIVKEY_SIZE          _MAX(DILITHIUM_3_65_PRIVKEY_SIZE, \
                                             DILITHIUM_3_87_PRIVKEY_SIZE)

#define DILITHIUM_3_65_SIG_SIZE         3293
#define DILITHIUM_3_87_SIG_SIZE         4595

#define MAX_DILITHIUM_65_MSG_SIZE       6000
#define MAX_DILITHIUM_87_MSG_SIZE       4000

#define PQA_ALGID_CRYS_DIL_R3           0x03

#define PQA_ALGPARM_CRYS_DIL_65         0x0605
#define PQA_ALGPARM_CRYS_DIL_87         0x0807


struct ica_mldsa_ctx {
	mldsa_variant_t variant;
	int priv_init;
	int pub_init;
	unsigned int rho_len;
	unsigned int t1_len;
	unsigned int seed_len;
	unsigned int tr_len;
	unsigned int s1_len;
	unsigned int s2_len;
	unsigned int t0_len;
	unsigned int publen;
	unsigned int privlen;
	unsigned int siglen;
	unsigned int max_msglen;
	unsigned char pubkey[MAX_MLDSA_PUBKEY_SIZE];
	unsigned char privkey[MAX_MLDSA_PRIVKEY_SIZE];
};

/*
 * QSA private key section
 */
typedef struct {
	uint8_t section_id; /* 0x50 = QSA private key */
	uint8_t version;
	uint16_t section_len;
	uint16_t associated_data_len; /* 54 bytes */
	uint8_t reserved1[2];
	uint8_t associated_data_version; /* = 0x01 */
	uint8_t algo_id; /* Dilithium round */
	uint16_t algo_params; /* Dilithium variant */
	uint8_t key_format;
	uint8_t key_src_flag_byte;
	uint8_t compliance_control_byte;
	uint8_t hash_type;
	uint16_t usage_bytes; /* 0x8000 = digitalSignature */
	uint8_t sha256_hash_over_public_key_section[32];
	uint16_t seed_len;
	uint16_t tr_len;
	uint16_t s1_len;
	uint16_t s2_len;
	uint16_t t0_len;
	uint8_t reserved2[2];
	uint8_t obj_protection_key[56];
	uint8_t kvp[8];
	uint8_t reserved3[2];
	/* Here comes the variable part: private key parts: (seed,tr,s1,s2,t0) */
} __attribute__((packed)) QSA_PRIVATE_KEY_SECTION;

/*
 * QSA public key section.
 */
typedef struct {
	uint8_t section_id; /* 0x51 = QSA public key */
	uint8_t version;
	uint16_t section_len;
	uint8_t key_format;
	uint8_t algo_id; /* Dilithium round */
	uint16_t algo_params; /* Dilithium variant */
	uint16_t usage_bytes; /* 0x8000 = digitalSignature */
	uint16_t rho_len;
	uint16_t t1_len;
	uint8_t reserved[10];
	/* Here comes the variable part: public key parts (rho,t1) */
} __attribute__((packed)) QSA_PUBLIC_KEY_SECTION;

/*
 * QSA private key token
 */
typedef struct {
	uint16_t key_len;
	uint16_t reserved;
	PKA_TOKEN_HDR tknhdr;
	QSA_PRIVATE_KEY_SECTION privsec;
	unsigned char privkey[0];
	/* Here comes the variable length private key */
} __attribute__((packed)) QSA_PRIVATE_KEY_TOKEN;

/*
 *  QSA public key token
 */
typedef struct {
	QSA_PUBLIC_KEY_SECTION pubsec;
	unsigned char pubkey[0];
	/* here comes the variable length public key (rho,t1) */
} __attribute__((packed)) QSA_PUBLIC_KEY_TOKEN;

/*
 * QSA parmblock.
 */
typedef struct {
	uint16_t subfunc_code;
	struct {
		uint16_t rule_array_len;
		uint8_t rule_array_cmd[16];
	} rule_array;
	struct {
		uint16_t vud_len;
		uint16_t vud1_len;
		uint8_t vud1[0];
		/* Here comes the variable length data to sign/verify */
	} vud_data;
} __attribute__((packed)) QSA_PARMBLOCK_PART1;

typedef struct {
	struct {
		uint16_t vud2_len;
		uint8_t vud2_data[0];
		/* Here comes the variable length signature to verify */
	} vud_data;
} __attribute__((packed)) QSA_PARMBLOCK_PART2;

/*
 * QSA verify public key block
 */
typedef struct {
	uint16_t key_len;
	uint8_t reserved[2];
	PKA_TOKEN_HDR tknhdr;
	QSA_PUBLIC_KEY_SECTION pubsec;
	unsigned char pubkey[0];
	/* Here come the variable length public key parts (rho, t1) */
} __attribute__((packed)) QSA_PUBLIC_KEY_BLOCK;

/*
 * QSA sign reply
 */
typedef struct {
	uint8_t reply_cprbx[sizeof(struct CPRBX)];
	uint8_t subfunc_code[2];
	uint16_t rule_len;
	uint16_t vud_len;
	uint8_t vud1[6];
	uint8_t signature[0];
	/* Here comes the variable length signature, siglen = vud_len - 6 - 2 */
} __attribute__((packed)) QSA_SIGN_REPLY;

/*
 * QSA verify reply
 */
typedef struct {
	uint8_t reply_cprbx[sizeof(struct CPRBX)];
	uint8_t subfunc_code[2];
	uint16_t rule_len;
	uint16_t vud_len;
	uint16_t keylen;
} __attribute__((packed)) QSA_VERIFY_REPLY;

/*
 * QSA KeyGen private key struct
 */
typedef struct {
	uint16_t key_len;
	uint16_t reserved1;
	PKA_TOKEN_HDR tknhdr;
	QSA_PRIVATE_KEY_SECTION privsec;
	QSA_PUBLIC_KEY_SECTION pubsec;
} __attribute__((packed)) QSA_KEYGEN_KEY_TOKEN;

/*
 * QSA KeyGen reply
 */
typedef struct {
	uint8_t reply_cprbx[sizeof(struct CPRBX)];
	uint8_t subfunc_code[2];
	uint16_t rule_len;
	uint16_t vud_len;
	uint16_t keyblock_len;
	QSA_PRIVATE_KEY_TOKEN qsakey;
} __attribute__((packed)) QSA_KEYGEN_REPLY;

/*
 * returns 1 if the ML-DSA / Dilithium variant is supported by CCA8 cards,
 * and all online cards are CCA8, 0 otherwise.
 */
static inline int mldsa_supported_via_online_card(mldsa_variant_t variant)
{
	if (!mldsa_via_online_card)
		return 0;

	switch (variant) {
	case DILITHIUM_3_65:
	case DILITHIUM_3_87:
		return 1;
	default:
		return 0;
	}
}

void mldsa_ctx_init(ICA_MLDSA_CTX *ctx, mldsa_variant_t variant);

unsigned int qsa_keygen_hw(ica_adapter_handle_t adapter_handle,
				ICA_MLDSA_CTX *ctx);

unsigned int qsa_verify_hw(ica_adapter_handle_t adapter_handle,
				const ICA_MLDSA_CTX *ctx,
				const unsigned char *signature, unsigned int siglen,
				const unsigned char *hash, unsigned int hash_length);

unsigned int qsa_sign_hw(ica_adapter_handle_t adapter_handle,
				ICA_MLDSA_CTX *ctx, unsigned char *sig,
				unsigned int *siglen,
				const unsigned char *msg, size_t msglen);

#endif /* S390_MLDSA_H */
