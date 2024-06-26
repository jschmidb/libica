/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Copyright IBM Corp. 2024
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "s390_cca.h"


/**
 * determines and returns the default domain. With older zcrypt drivers
 * it's not possible to specify 0xffff to indicate 'any domain' in a
 * request CPRB.
 *
 * @return domain number (0 ... n, machine dependent) if success
 *         -1 if error or driver not loaded
 */
short get_default_domain(void)
{
	const char *domainfile = "/sys/bus/ap/ap_domain";
	static short domain = -1;
	int temp;
	FILE *f;

	f = fopen(domainfile, "r");
	if (!f)
		return domain;

	if (fscanf(f, "%d", &temp) != 1)
		goto done;

	domain = (short)temp;

done:
	if (f)
		fclose(f);

	return domain;
}

/**
 * makes a PKA keyblock length field at given struct and returns its length.
 */
unsigned int make_pka_keyblock_length(PKA_KEYBLOCK_LENGTH *kb, unsigned int len)
{
	kb->keyblock_len = len;

	return sizeof(PKA_KEYBLOCK_LENGTH);
}

/**
 * makes a PKA null token at given struct and returns its length.
 */
unsigned int make_pka_null_token(PKA_NULL_TOKEN *kb)
{
	kb->len = 0x0005;
	kb->flags = 0x0010;
	kb->nulltoken = 0x00;

	return sizeof(PKA_NULL_TOKEN);
}

/**
 * makes a T2 CPRBX at given struct and returns its length.
 */
unsigned int make_cprbx(struct CPRBX* cprbx, unsigned int parmlen,
		struct CPRBX *preqcblk, struct CPRBX *prepcblk,
		dom_addressing_t dom_addressing)
{
	cprbx->cprb_len = CPRBXSIZE;
	cprbx->cprb_ver_id = 0x02;
	memcpy(&(cprbx->func_id), "T2", 2);
	cprbx->req_parml = parmlen;
	if (dom_addressing == dom_addressing_autoselect)
		cprbx->domain = 0xFFFF;
	else
		cprbx->domain = get_default_domain();
	cprbx->rpl_msgbl = CPRBXSIZE + PARMBSIZE;
	cprbx->req_parmb = ((uint8_t *) preqcblk) + CPRBXSIZE;
	cprbx->rpl_parmb = ((uint8_t *) prepcblk) + CPRBXSIZE;

	return CPRBXSIZE;
}

/**
 * finalizes an ica_xcRB struct that is sent to the card.
 */
void finalize_xcrb(struct ica_xcRB* xcrb, struct CPRBX *preqcblk,
						struct CPRBX *prepcblk)
{
	memset(xcrb, 0, sizeof(struct ica_xcRB));
	xcrb->agent_ID = 0x4341;
	xcrb->user_defined = AUTOSELECT; /* use any card number */
	xcrb->request_control_blk_length = preqcblk->cprb_len + preqcblk->req_parml;
	xcrb->request_control_blk_addr = (void *) preqcblk;
	xcrb->reply_control_blk_length = preqcblk->rpl_msgbl;
	xcrb->reply_control_blk_addr = (void *) prepcblk;
}

/**
 * makes a PKA clear-key KeyGen parmblock at given struct and returns
 * its length.
 */
unsigned int make_pka_keygen_parmblock(PKA_KEYGEN_PARMBLOCK *pb)
{
	pb->subfunc_code = 0x5047; /* 'PG' */
	pb->rule_array.rule_array_len = 0x000A;
	memcpy(&(pb->rule_array.rule_array_cmd), "CLEAR   ", 8);
	pb->vud_len = 0x0002;

	return sizeof(PKA_KEYGEN_PARMBLOCK);
}
