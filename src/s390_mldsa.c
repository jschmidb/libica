/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Copyright IBM Corp. 2024
 */

#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include <openssl/crypto.h>

#include "fips.h"
#include "s390_crypto.h"
#include "s390_common.h"
#include "s390_mldsa.h"
#include "init.h"
#include "icastats.h"


/* Public key */
const unsigned int variant2publen[] = {
	DILITHIUM_3_65_PUBKEY_SIZE,
	DILITHIUM_3_87_PUBKEY_SIZE
};

const uint16_t variant2rho_len[] = {
	DILITHIUM_3_65_RHO_SIZE,
	DILITHIUM_3_87_RHO_SIZE
};

const uint16_t variant2t1_len[] = {
	DILITHIUM_3_65_T1_SIZE,
	DILITHIUM_3_87_T1_SIZE
};

/* Private key */
const unsigned int variant2privlen[] = {
	DILITHIUM_3_65_PRIVKEY_SIZE,
	DILITHIUM_3_87_PRIVKEY_SIZE
};

const uint16_t variant2seed_len[] = {
	DILITHIUM_3_65_SEED_SIZE,
	DILITHIUM_3_87_SEED_SIZE
};

const uint16_t variant2tr_len[] = {
	DILITHIUM_3_65_TR_SIZE,
	DILITHIUM_3_87_TR_SIZE
};

const uint16_t variant2s1_len[] = {
	DILITHIUM_3_65_S1_SIZE,
	DILITHIUM_3_87_S1_SIZE
};

const uint16_t variant2s2_len[] = {
	DILITHIUM_3_65_S2_SIZE,
	DILITHIUM_3_87_S2_SIZE
};

const uint16_t variant2t0_len[] = {
	DILITHIUM_3_65_T0_SIZE,
	DILITHIUM_3_87_T0_SIZE
};

/* Algorithm ID and parameters */
const uint8_t variant2algo_id[] = {
	PQA_ALGID_CRYS_DIL_R3,
	PQA_ALGID_CRYS_DIL_R3
};

const uint16_t variant2algo_params[] = {
	PQA_ALGPARM_CRYS_DIL_65,
	PQA_ALGPARM_CRYS_DIL_87
};

const unsigned int variant2siglen[] = {
	DILITHIUM_3_65_SIG_SIZE,
	DILITHIUM_3_87_SIG_SIZE
};

const unsigned int variant2maxmsglen[] = {
	MAX_DILITHIUM_65_MSG_SIZE,
	MAX_DILITHIUM_87_MSG_SIZE
};

/**
 * makes a QSA sign parmblock at given struct and returns its length.
 *
 * Note: Do not use the MESSAGE rule array keyword here. It's even recommended
 *       in the CCA Application Programmer's Guide, but the card request
 *       fails when specified here.
 */
static unsigned int make_qsa_sign_parmblock(QSA_PARMBLOCK_PART1 *pb,
						const unsigned char *msg, unsigned int msglen)
{
	pb->subfunc_code = 0x5347; /* 'SG' */
	pb->rule_array.rule_array_len = 0x0012; /* subfunc_code + rule array cmds */
	memcpy(&(pb->rule_array.rule_array_cmd), "CRDL-DSACRDLHASH", 2 * 8);
	pb->vud_data.vud_len = msglen + 4;
	pb->vud_data.vud1_len = msglen + 2;
	memcpy(&(pb->vud_data.vud1), msg, msglen);

	return sizeof(QSA_PARMBLOCK_PART1) + msglen;
}

/**
 * makes a QSA sign private key token at given struct and returns its length.
 */
static unsigned int make_qsa_sign_private_key_token(
						const ICA_MLDSA_CTX *ctx, unsigned char *kb)
{
	QSA_PRIVATE_KEY_TOKEN *kp1;
	QSA_PUBLIC_KEY_TOKEN *kp2;

	unsigned int qsakey_length = 2 + 2 + sizeof(PKA_TOKEN_HDR)
			+ sizeof(QSA_PRIVATE_KEY_SECTION) + ctx->privlen
			+ sizeof(QSA_PUBLIC_KEY_TOKEN) + ctx->publen;

	kp1 = (QSA_PRIVATE_KEY_TOKEN *)kb;
	kp2 = (QSA_PUBLIC_KEY_TOKEN *)(kb + sizeof(QSA_PRIVATE_KEY_TOKEN) + ctx->privlen);

	kp1->key_len = qsakey_length;
	kp1->tknhdr.tkn_hdr_id = 0x1E;
	kp1->tknhdr.tkn_length = qsakey_length - 2 - 2; /* 2x len field */

	kp1->privsec.section_id = 0x50; /* QSA private key */
	kp1->privsec.section_len = sizeof(QSA_PRIVATE_KEY_SECTION) + ctx->privlen;
	kp1->privsec.associated_data_len = 54;
	kp1->privsec.associated_data_version = 0x01;
	kp1->privsec.algo_id = variant2algo_id[ctx->variant];
	kp1->privsec.algo_params = variant2algo_params[ctx->variant];
	kp1->privsec.usage_bytes = 0x8000;
	kp1->privsec.seed_len = (uint16_t)ctx->seed_len;
	kp1->privsec.tr_len = (uint16_t)ctx->tr_len;
	kp1->privsec.s1_len = (uint16_t)ctx->s1_len;
	kp1->privsec.s2_len = (uint16_t)ctx->s2_len;
	kp1->privsec.t0_len = (uint16_t)ctx->t0_len;
	memcpy(kp1->privkey, ctx->privkey, ctx->privlen); /* copies all priv parts */

	kp2->pubsec.section_id = 0x51; /* QSA public key */
	kp2->pubsec.section_len =  sizeof(QSA_PUBLIC_KEY_SECTION) + ctx->publen;
	kp2->pubsec.algo_id = variant2algo_id[ctx->variant];
	kp2->pubsec.algo_params = variant2algo_params[ctx->variant];
	kp2->pubsec.usage_bytes = 0x8000;
	kp2->pubsec.rho_len = (uint16_t)ctx->rho_len;
	kp2->pubsec.t1_len = (uint16_t)ctx->t1_len;
	memcpy(kp2->pubkey, ctx->pubkey, ctx->publen); /* copies rho and t1 */

	return sizeof(QSA_PRIVATE_KEY_TOKEN) + ctx->privlen
			+ sizeof(QSA_PUBLIC_KEY_TOKEN) + ctx->publen;
}

/**
 * creates a QSA sign request message for zcrypt.
 *
 * returns a pointer to the control block where the card
 * provides its reply.
 *
 * The function allocates len bytes at cbrbmem. The caller
 * is responsible to erase sensible data and free the
 * memory.
 */
static QSA_SIGN_REPLY* make_qsa_sign_request(const ICA_MLDSA_CTX *ctx,
				const unsigned char *msg, size_t msglen,
				struct ica_xcRB* xcrb, uint8_t **cbrbmem, size_t *len,
				dom_addressing_t dom_addressing)
{
	struct CPRBX *preqcblk, *prepcblk;
	unsigned int qsa_key_token_len = 2 + 2 + sizeof(PKA_TOKEN_HDR)
		+ sizeof(QSA_PRIVATE_KEY_SECTION) + ctx->privlen
		+ sizeof(QSA_PUBLIC_KEY_TOKEN) + ctx->publen;

	unsigned int keyblock_len = 2 + qsa_key_token_len;
	unsigned int parmblock_len = sizeof(QSA_PARMBLOCK_PART1)
		+ msglen + keyblock_len;

	/* allocate buffer space for req cprb, req parm, rep cprb, rep parm */
	*len = 2 * (CPRBXSIZE + PARMBSIZE);
	*cbrbmem = malloc(*len);
	if (!*cbrbmem)
		return NULL;

	memset(*cbrbmem, 0, *len);
	preqcblk = (struct CPRBX *) *cbrbmem;
	prepcblk = (struct CPRBX *) (*cbrbmem + CPRBXSIZE + PARMBSIZE);

	/* make QSA sign request */
	unsigned int offset = 0;
	offset = make_cprbx((struct CPRBX *)*cbrbmem, parmblock_len, preqcblk, prepcblk, dom_addressing);
	offset += make_qsa_sign_parmblock((QSA_PARMBLOCK_PART1 *)(*cbrbmem + offset), msg, msglen);
	offset += make_pka_keyblock_length((PKA_KEYBLOCK_LENGTH *)(*cbrbmem + offset), keyblock_len);
	offset += make_qsa_sign_private_key_token(ctx, *cbrbmem + offset);
	finalize_xcrb(xcrb, preqcblk, prepcblk);

	return (QSA_SIGN_REPLY *)prepcblk;
}

/**
 * creates an ML-DSA signature via Crypto Express CCA coprocessor.
 *
 * Returns 0 if successful
 *         EIO if an internal error occurred
 */
unsigned int qsa_sign_hw(ica_adapter_handle_t adapter_handle,
				ICA_MLDSA_CTX *ctx, unsigned char *sig, unsigned int *siglen,
				const unsigned char *msg, size_t msglen)
{
	struct ica_xcRB xcrb;
	QSA_SIGN_REPLY* reply_p;
	uint8_t *buf = NULL;
	size_t len;
	int rc;

	reply_p = make_qsa_sign_request(ctx, msg, msglen, &xcrb, &buf, &len,
								dom_addressing_autoselect);
	if (!reply_p) {
		rc = EIO;
		goto ret;
	}

	rc = ioctl(adapter_handle, ZSECSENDCPRB, xcrb);
	if (rc != 0) {
		reply_p = make_qsa_sign_request(ctx, msg, msglen, &xcrb, &buf, &len,
								dom_addressing_default_domain);
		if (!reply_p) {
			rc = EIO;
			goto ret;
		}

		rc = ioctl(adapter_handle, ZSECSENDCPRB, xcrb);
		if (rc != 0) {
			rc = EIO;
			goto ret;
		}
	}

	if ((unsigned int)reply_p->vud_len - 8 != ctx->siglen) {
		rc = EIO;
		goto ret;
	}

	*siglen = ctx->siglen;
	memcpy(sig, reply_p->signature, *siglen);

	rc = 0;

ret:
	if (buf) {
		OPENSSL_cleanse(buf, len);
		free(buf);
	}

	return rc;
}

/**
 * makes a QSA verify key structure at given struct and returns its length.
 */
static unsigned int make_qsa_public_key_token(QSA_PUBLIC_KEY_BLOCK *kb,
						const ICA_MLDSA_CTX *ctx)
{
	unsigned int this_length = sizeof(QSA_PUBLIC_KEY_BLOCK) + ctx->publen;

	kb->key_len = this_length;
	kb->tknhdr.tkn_hdr_id = 0x1E;
	kb->tknhdr.tkn_length = this_length - 2 - 2; /* 2x len field */

	kb->pubsec.section_id = 0x51;
	kb->pubsec.section_len = sizeof(QSA_PUBLIC_KEY_TOKEN) + ctx->publen;
	kb->pubsec.algo_id = variant2algo_id[ctx->variant];
	kb->pubsec.algo_params = variant2algo_params[ctx->variant];
	kb->pubsec.usage_bytes = 0x8000;
	kb->pubsec.rho_len = ctx->rho_len;
	kb->pubsec.t1_len = ctx->t1_len;

	memcpy(kb->pubkey, ctx->pubkey, ctx->publen); /* copies both, rho and t1 */

	return this_length;
}

/**
 * makes a QSA verify parmblock at given struct and returns its length.
 */
static unsigned int make_qsa_verify_parmblock(char *pb,
				const unsigned char *msg, unsigned int msglen,
				const unsigned char *signature, unsigned int signature_len)
{
	QSA_PARMBLOCK_PART1 *pb1;
	QSA_PARMBLOCK_PART2 *pb2;

	pb1 = (QSA_PARMBLOCK_PART1 *)pb;
	pb2 = (QSA_PARMBLOCK_PART2 *)(pb + sizeof(QSA_PARMBLOCK_PART1) + msglen);

	pb1->subfunc_code = 0x5356; /* 'SV' */
	pb1->rule_array.rule_array_len = 0x0012; /* subfunc_code + rule array cmds */
	memcpy(&(pb1->rule_array.rule_array_cmd), "CRDL-DSACRDLHASH", 2 * 8);
	pb1->vud_data.vud_len = 2 + (2 + msglen) + (2 + signature_len);
	pb1->vud_data.vud1_len = 2 + msglen;
	memcpy(&(pb1->vud_data.vud1), msg, msglen);

	pb2->vud_data.vud2_len = 2 + signature_len;
	memcpy(&(pb2->vud_data.vud2_data), signature, signature_len);

	return sizeof(QSA_PARMBLOCK_PART1)
			+ msglen
			+ sizeof(QSA_PARMBLOCK_PART2)
			+ signature_len;
}

/**
 * creates a QSA xcrb request message for zcrypt.
 *
 * returns a pointer to the control block where the card
 * provides its reply.
 *
 * The function allocates len bytes at cbrbmem. The caller
 * is responsible to erase sensible data and free the
 * memory.
 */
static QSA_VERIFY_REPLY* make_qsa_verify_request(const ICA_MLDSA_CTX *ctx,
					const unsigned char *hash, unsigned int hash_length,
					const unsigned char *signature, unsigned int siglen,
					struct ica_xcRB* xcrb, uint8_t **cbrbmem, size_t *len,
					dom_addressing_t dom_addressing)
{
	struct CPRBX *preqcblk, *prepcblk;

	unsigned int qsa_key_token_len = 2 + 2 + sizeof(PKA_TOKEN_HDR)
		+ sizeof(QSA_PUBLIC_KEY_TOKEN) + ctx->publen;

	unsigned int keyblock_len = 2 + qsa_key_token_len;
	unsigned int parmblock_len = sizeof(QSA_PARMBLOCK_PART1) + hash_length
		+ sizeof(QSA_PARMBLOCK_PART2) + siglen + keyblock_len;

	/* allocate buffer space for req cprb, req parm, rep cprb, rep parm */
	*len = 2 * (CPRBXSIZE + PARMBSIZE);
	*cbrbmem = malloc(*len);
	if (!*cbrbmem)
		return NULL;

	memset(*cbrbmem, 0, *len);
	preqcblk = (struct CPRBX *) *cbrbmem;
	prepcblk = (struct CPRBX *) (*cbrbmem + CPRBXSIZE + PARMBSIZE);

	/* make QSA verify request */
	unsigned int offset = 0;
	offset = make_cprbx((struct CPRBX *)*cbrbmem, parmblock_len, preqcblk, prepcblk, dom_addressing);
	offset += make_qsa_verify_parmblock((char*)(*cbrbmem+offset), hash, hash_length, signature, siglen);
	offset += make_pka_keyblock_length((PKA_KEYBLOCK_LENGTH*)(*cbrbmem + offset), keyblock_len);
	offset += make_qsa_public_key_token((QSA_PUBLIC_KEY_BLOCK*)(*cbrbmem + offset), ctx);
	finalize_xcrb(xcrb, preqcblk, prepcblk);

	return (QSA_VERIFY_REPLY*)prepcblk;
}

/**
 * verifies a QSA signature via Crypto Express CCA coprocessor.
 *
 * Returns 0 if successful
 *         EFAULT if signature invalid
 *         EIO if an internal error occurred
 */
unsigned int qsa_verify_hw(ica_adapter_handle_t adapter_handle,
				const ICA_MLDSA_CTX *ctx,
				const unsigned char *signature, unsigned int siglen,
				const unsigned char *hash, unsigned int hash_length)
{
	struct ica_xcRB xcrb;
	QSA_VERIFY_REPLY* reply_p;
	uint8_t *buf = NULL;
	size_t len;
	int rc;

	if (adapter_handle == DRIVER_NOT_LOADED)
		return EIO;

	reply_p = make_qsa_verify_request(ctx, hash, hash_length,
					signature, siglen, &xcrb, &buf, &len,
					dom_addressing_autoselect);
	if (!reply_p) {
		rc = EIO;
		goto ret;
	}

	rc = ioctl(adapter_handle, ZSECSENDCPRB, xcrb);
	if (rc != 0) {
		reply_p = make_qsa_verify_request(ctx, hash, hash_length,
						signature, siglen, &xcrb, &buf, &len,
						dom_addressing_default_domain);
		if (!reply_p) {
			rc = EIO;
			goto ret;
		}

		rc = ioctl(adapter_handle, ZSECSENDCPRB, xcrb);
		if (rc != 0) {
			rc = EIO;
			goto ret;
		}
	}

	/*
	 * Refer to CCA Application Programmer's Guide, Return and Reason codes:
	 * (4, 429) The digital signature is not verified. The verb completed
	 *          its processing normally.
	 */
	if (((struct CPRBX*)reply_p)->ccp_rtcode == 4 &&
		((struct CPRBX*)reply_p)->ccp_rscode == 429) {
		rc = EFAULT;
		goto ret;
	}

	if (((struct CPRBX*)reply_p)->ccp_rtcode != 0 ||
		((struct CPRBX*)reply_p)->ccp_rscode != 0) {
		rc = EIO;
		goto ret;
	}

	rc = 0;

ret:
	if (buf) {
		OPENSSL_cleanse(buf, len);
		free(buf);
	}

	return rc;
}

/**
 * makes a QSA KeyGen private key structure at given struct and
 * returns its length.
 */
static unsigned int make_qsa_keygen_private_key_token(ICA_MLDSA_CTX *ctx,
												QSA_KEYGEN_KEY_TOKEN* kb)
{
	kb->key_len = sizeof(QSA_KEYGEN_KEY_TOKEN);
	kb->tknhdr.tkn_hdr_id = 0x1E;
	kb->tknhdr.tkn_length = sizeof(QSA_KEYGEN_KEY_TOKEN) - 2 - 2; /* 2x len field */

	kb->privsec.section_id = 0x50; /* QSA private key */
	kb->privsec.section_len = sizeof(QSA_PRIVATE_KEY_SECTION);
	kb->privsec.associated_data_len = 54;
	kb->privsec.associated_data_version = 0x01;
	kb->privsec.algo_id = variant2algo_id[ctx->variant];
	kb->privsec.algo_params = variant2algo_params[ctx->variant];
	kb->privsec.usage_bytes = 0x8000;

	kb->pubsec.section_id = 0x51; /* QSA public key */
	kb->pubsec.section_len =  sizeof(QSA_PUBLIC_KEY_SECTION);
	kb->pubsec.algo_id = variant2algo_id[ctx->variant];
	kb->pubsec.algo_params = variant2algo_params[ctx->variant];
	kb->pubsec.usage_bytes = 0x8000;

	return sizeof(QSA_KEYGEN_KEY_TOKEN);
}

/**
 * creates a QSA KeyGen xcrb request message for zcrypt.
 *
 * returns a pointer to the control block where the card
 * provides its reply.
 *
 * The function allocates len bytes at cbrbmem. The caller
 * is responsible to erase sensible data and free the
 * memory.
 */
static QSA_KEYGEN_REPLY* make_qsa_keygen_request(ICA_MLDSA_CTX *ctx,
					struct ica_xcRB* xcrb, uint8_t **cbrbmem, size_t *len,
					dom_addressing_t dom_addressing)
{
	struct CPRBX *preqcblk, *prepcblk;

	unsigned int keyblock_len = 2 + sizeof(QSA_KEYGEN_KEY_TOKEN)
		+ sizeof(PKA_NULL_TOKEN);
	unsigned int parmblock_len = sizeof(PKA_KEYGEN_PARMBLOCK) + keyblock_len;

	/* allocate buffer space for req cprb, req parm, rep cprb, rep parm */
	*len = 2 * (CPRBXSIZE + PARMBSIZE);
	*cbrbmem = malloc(*len);
	if (!*cbrbmem)
		return NULL;

	memset(*cbrbmem, 0, *len);
	preqcblk = (struct CPRBX *) *cbrbmem;
	prepcblk = (struct CPRBX *) (*cbrbmem + CPRBXSIZE + PARMBSIZE);

	/* make QSA KeyGen request */
	unsigned int offset = 0;
	offset = make_cprbx((struct CPRBX *)*cbrbmem, parmblock_len, preqcblk, prepcblk, dom_addressing);
	offset += make_pka_keygen_parmblock((PKA_KEYGEN_PARMBLOCK*)(*cbrbmem + offset));
	offset += make_pka_keyblock_length((PKA_KEYBLOCK_LENGTH*)(*cbrbmem+offset), keyblock_len);
	offset += make_qsa_keygen_private_key_token(ctx, (QSA_KEYGEN_KEY_TOKEN*)(*cbrbmem + offset));
	offset += make_pka_null_token((PKA_NULL_TOKEN*)(*cbrbmem+offset));
	finalize_xcrb(xcrb, preqcblk, prepcblk);

	return (QSA_KEYGEN_REPLY*)prepcblk;
}

/**
 * generates a QSA key via Crypto Express CCA coprocessor.
 * Requires a CEX8C.
 *
 * Returns 0 if successful
 *         EIO if an internal error occurred.
 */
unsigned int qsa_keygen_hw(ica_adapter_handle_t adapter_handle,
					ICA_MLDSA_CTX *ctx)
{
	struct ica_xcRB xcrb;
	QSA_KEYGEN_REPLY *reply_p;
	QSA_PUBLIC_KEY_TOKEN *pub_p;
	uint8_t *buf = NULL;
	size_t len;
	int rc;

	unsigned char* p;

	reply_p = make_qsa_keygen_request(ctx, &xcrb, &buf, &len,
						dom_addressing_autoselect);
	if (!reply_p) {
		rc = EIO;
		goto ret;
	}

	rc = ioctl(adapter_handle, ZSECSENDCPRB, xcrb);
	if (rc != 0) {
		reply_p = make_qsa_keygen_request(ctx, &xcrb, &buf, &len,
						dom_addressing_default_domain);
		if (!reply_p) {
			rc = EIO;
			goto ret;
		}

		rc = ioctl(adapter_handle, ZSECSENDCPRB, xcrb);
		if (rc != 0) {
			rc = EIO;
			goto ret;
		}
	}

	p = (unsigned char*)&(reply_p->qsakey.privsec) + reply_p->qsakey.privsec.section_len;
	pub_p = (QSA_PUBLIC_KEY_TOKEN*)p;

	if (pub_p->pubsec.rho_len != ctx->rho_len ||
		pub_p->pubsec.t1_len != ctx->t1_len ||
		reply_p->qsakey.privsec.seed_len != ctx->seed_len ||
		reply_p->qsakey.privsec.tr_len != ctx->tr_len ||
		reply_p->qsakey.privsec.s1_len != ctx->s1_len ||
		reply_p->qsakey.privsec.s2_len != ctx->s2_len ||
		reply_p->qsakey.privsec.t0_len != ctx->t0_len) {
		rc = EIO;
		goto ret;
	}

	memcpy(ctx->pubkey, pub_p->pubkey, ctx->publen);
	memcpy(ctx->privkey, reply_p->qsakey.privkey, ctx->privlen);

	rc = 0;

ret:
	if (buf) {
		OPENSSL_cleanse(buf, len);
		free(buf);
	}

	return rc;
}

void mldsa_ctx_init(ICA_MLDSA_CTX *ctx, mldsa_variant_t variant)
{
	ctx->variant = variant;

	ctx->rho_len = variant2rho_len[variant];
	ctx->t1_len = variant2t1_len[variant];

	ctx->seed_len = variant2seed_len[variant];
	ctx->tr_len = variant2tr_len[variant];
	ctx->s1_len = variant2s1_len[variant];
	ctx->s2_len = variant2s2_len[variant];
	ctx->t0_len = variant2t0_len[variant];

	ctx->privlen = variant2privlen[variant];
	ctx->publen = variant2publen[variant];
	ctx->siglen = variant2siglen[variant];
	ctx->max_msglen = variant2maxmsglen[variant];
}
