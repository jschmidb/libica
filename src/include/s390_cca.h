/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

#ifndef S390_CCA_H
#define S390_CCA_H

#include <asm/zcrypt.h>

#define CPRBXSIZE (sizeof(struct CPRBX))
#define PARMBSIZE (8192)

/*
 * Since kernel 4.10 the zcrypt device driver has multi domain support and
 * accepts CPRBs via the ioctl ZSECSENDCPRB with domain addressing 0xFFFF
 * (AUTOSELECT_DOM in zcrypyt.h). This allows for load balancing between
 * multiple available crypto cards.
 */
typedef enum {
	dom_addressing_autoselect = 0,
	dom_addressing_default_domain,
} dom_addressing_t;

/*
 * PKA key token header.
 */
typedef struct {
	uint8_t tkn_hdr_id; /* 0x1E - PKA external key-token */
	uint8_t tkn_hdr_version; /* version = 0x00 */
	uint16_t tkn_length;
	uint8_t reserved[4];
} __attribute__((packed)) PKA_TOKEN_HDR;

/*
 * PKA keyblock, just the length field.
 */
typedef struct {
	uint16_t keyblock_len;
} __attribute__((packed)) PKA_KEYBLOCK_LENGTH;

/*
 * A PKA null token.
 */
typedef struct {
	uint16_t len;
	uint16_t flags;
	uint8_t nulltoken;
} __attribute__((packed)) PKA_NULL_TOKEN;

/*
 * PKA KeyGen parmblock
 */
typedef struct {
	uint16_t subfunc_code;
	struct {
		uint16_t rule_array_len;
		uint8_t rule_array_cmd[8];
	} rule_array;
	uint16_t vud_len; /* no data, only len field */
} __attribute__((packed)) PKA_KEYGEN_PARMBLOCK;

/*
 * Prototypes
 */
short get_default_domain(void);
unsigned int make_pka_keyblock_length(PKA_KEYBLOCK_LENGTH *kb,
		unsigned int len);
unsigned int make_pka_keygen_parmblock(PKA_KEYGEN_PARMBLOCK *pb);
unsigned int make_pka_null_token(PKA_NULL_TOKEN *kb);
unsigned int make_cprbx(struct CPRBX* cprbx, unsigned int parmlen,
		struct CPRBX *preqcblk, struct CPRBX *prepcblk,
		dom_addressing_t dom_addressing);
void finalize_xcrb(struct ica_xcRB* xcrb, struct CPRBX *preqcblk,
		struct CPRBX *prepcblk);

#endif /* S390_CCA_H */
