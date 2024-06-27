#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "ica_api.h"
#include "mldsa_test.h"
#include "testcase.h"


typedef struct {
	unsigned int variant;
	char id_str[32];
	unsigned int msglen;
} mldsa_variant_test_t;

static mldsa_variant_test_t mldsa_test[] = {
	{DILITHIUM_3_65, "Dilithium 3 (6,5)", 0},
	{DILITHIUM_3_65, "Dilithium 3 (6,5)", 1},
	{DILITHIUM_3_65, "Dilithium 3 (6,5)", 33},
	{DILITHIUM_3_65, "Dilithium 3 (6,5)", 3333},
	{DILITHIUM_3_65, "Dilithium 3 (6,5)", 6000},
	{DILITHIUM_3_87, "Dilithium 3 (8,7)", 0},
	{DILITHIUM_3_87, "Dilithium 3 (8,7)", 1},
	{DILITHIUM_3_87, "Dilithium 3 (8,7)", 33},
	{DILITHIUM_3_87, "Dilithium 3 (8,7)", 444},
	{DILITHIUM_3_87, "Dilithium 3 (8,7)", 4000},
};
size_t num_mldsa_variants = sizeof(mldsa_test) / sizeof(mldsa_variant_test_t);

int mldsa_via_online_card(void)
{
	ICA_MLDSA_CTX *ctx = NULL;

	if (ica_mldsa_ctx_new(&ctx, DILITHIUM_3_65))
		return 0;

	ica_mldsa_ctx_free(&ctx);

	return 1;
}

void do_MLDSA_Keygen(ica_adapter_handle_t adapter_handle)
{
	unsigned char msg[6000];
	unsigned char signature[5000];
	unsigned int siglen = sizeof(signature);
	ICA_MLDSA_CTX *ctx = NULL;
	size_t i;
	int rc;

	memset(msg, 'a', sizeof(msg));

	for (i = 0; i < num_mldsa_variants; i++) {

		V_(printf("\nTesting %s keygen sign/verify with msglen = %d\n",
				mldsa_test[i].id_str, mldsa_test[i].msglen));

		rc = ica_mldsa_ctx_new(&ctx, mldsa_test[i].variant);
		if (rc || !ctx)
			EXIT_ERR("ica_mldsa_ctx_new failed.");

		if (ica_mldsa_key_gen(adapter_handle, ctx))
			EXIT_ERR("ica_mldsa_key_gen failed.");

		if (ica_mldsa_sign(adapter_handle, ctx, NULL, &siglen, msg,
						mldsa_test[i].msglen))
			EXIT_ERR("ica_mldsa_sign (length only) failed.");

		if (ica_mldsa_sign(adapter_handle, ctx, signature, &siglen, msg,
						mldsa_test[i].msglen))
			EXIT_ERR("ica_mldsa_sign failed.");

		if (ica_mldsa_verify(adapter_handle, ctx, signature, siglen,
						msg, mldsa_test[i].msglen))
			EXIT_ERR("ica_mldsa_verify failed.");

		if (ica_mldsa_ctx_free(&ctx))
			EXIT_ERR("ica_mldsa_ctx_free failed.");

		VV_(printf("--- Passed. ---\n"));
	}

	VV_(printf("All ML-DSA keygen tests passed.\n"));
}

void do_MLDSA_KAT(ica_adapter_handle_t adapter_handle)
{
	unsigned char pubkey[5000], pubbuf[5000];
	unsigned char privkey[8000], privbuf[8000];
	const struct mldsa_kat_tv *tv;
	unsigned char signature[5000];
	unsigned int siglen = sizeof(signature);
	unsigned int pubkey_len, privkey_len;
	unsigned int pubbuf_len, privbuf_len;
	ICA_MLDSA_CTX *ctx = NULL;
	size_t i, offset;
	int rc;

	for (i = 0; i < MLDSA_TV_LEN; i++) {

		tv = &MLDSA_TV[i];

		VV_(printf("\nTesting %s\n", tv->name));

		if (ica_fips_status() & ICA_FIPS_MODE) {
			V_(printf("Skipping %s, because not allowed in fips mode"
				" on this system.\n", tv->name));
			continue;
		}

		memset(signature, 0, sizeof(signature));

		rc = ica_mldsa_ctx_new(&ctx, tv->variant);
		if (rc || !ctx)
			EXIT_ERR("ica_mldsa_ctx_new failed.");

		/* Concatenate public and private key parts */
		memcpy(pubkey, tv->rho, tv->rho_len);
		memcpy(pubkey + tv->rho_len, tv->t1, tv->t1_len);
		pubkey_len = tv->rho_len + tv->t1_len;
		offset = 0;
		memcpy(privkey, tv->seed, tv->seed_len);
		offset += tv->seed_len;
		memcpy(privkey + offset, tv->tr, tv->tr_len);
		offset += tv->tr_len;
		memcpy(privkey + offset, tv->s1, tv->s1_len);
		offset += tv->s1_len;
		memcpy(privkey + offset, tv->s2, tv->s2_len);
		offset += tv->s2_len;
		memcpy(privkey + offset, tv->t0, tv->t0_len);
		privkey_len = offset + tv->t0_len;

		/* Set key */
		if (ica_mldsa_key_set(ctx, pubkey, pubkey_len, privkey, privkey_len))
			EXIT_ERR("ica_mldsa_key_set failed.");

		/* Get key: length only */
		if (ica_mldsa_key_get(ctx, NULL, &pubbuf_len, NULL, &privbuf_len))
			EXIT_ERR("ica_mldsa_key_get failed.");

		if (pubbuf_len != pubkey_len || privbuf_len != privkey_len)
			EXIT_ERR("ica_mldsa_key_get (length only) failed.");

		/* Get key and check if key parts unchanged */
		pubbuf_len = sizeof(pubbuf);
		privbuf_len = sizeof(privbuf);
		if (ica_mldsa_key_get(ctx, pubbuf, &pubbuf_len, privbuf, &privbuf_len))
			EXIT_ERR("ica_mldsa_key_get failed.");

		if (memcmp(pubbuf, pubkey, pubbuf_len) != 0 ||
			memcmp(privbuf, privkey, privbuf_len) != 0)
			EXIT_ERR("ica_mldsa_key_get: key parts not identical after get.");

		/* Obtain length of signature */
		if (ica_mldsa_sign(adapter_handle, ctx, NULL, &siglen,
						tv->msg, tv->msg_len))
			EXIT_ERR("ica_mldsa_sign (length only) failed");

		/* Sign */
		if (ica_mldsa_sign(adapter_handle, ctx, signature, &siglen,
						tv->msg, tv->msg_len))
			EXIT_ERR("ica_mldsa_sign failed.");

		/* Check if obtained length matches with expected length */
		if (siglen != tv->sig_len)
			EXIT_ERR("ica_mldsa_sign returned invalid signature length.");

		/* Check if obtained signature matches with expected signature */
		if (memcmp(signature, tv->sig, tv->sig_len))
			EXIT_ERR("ica_mldsa_sign returned invalid signature.");

		/* Verify */
		if (ica_mldsa_verify(adapter_handle, ctx, signature, siglen,
						tv->msg, tv->msg_len))
			EXIT_ERR("ica_mldsa_verify failed.");

		/* Flip a random bit and re-verify, must fail now */
		signature[rand() % tv->sig_len] ^= (1 << (rand() % 8));
		if (!ica_mldsa_verify(adapter_handle, ctx, signature, tv->sig_len,
							tv->msg, tv->msg_len))
			EXIT_ERR("ica_mldsa_verify succeeded with invalid signature.");

		if (ica_mldsa_ctx_free(&ctx))
			EXIT_ERR("ica_mldsa_ctx_free failed.");

		VV_(printf("--- Passed. ---\n"));
	}

	VV_(printf("All ML-DSA KATs passed.\n"));
}

int main(int argc, char **argv)
{
	ica_adapter_handle_t adapter_handle;
	int rc;

	set_verbosity(argc, argv);

	if (ica_fips_status() & ICA_FIPS_MODE) {
		V_(printf("Skipping ML-DSA tests, because not allowed in fips mode"
			" on this system.\n"));
		return TEST_SKIP;
	}

	if (!mldsa_via_online_card()) {
		printf("Skipping ML-DSA keygen test, because the required HW"
			" is not available on this machine.\n");
		return TEST_SKIP;
	}

	rc = ica_open_adapter(&adapter_handle);
	if (rc != 0) {
		V_(printf("ica_open_adapter failed and returned %d (0x%x).\n", rc, rc));
		return TEST_FAIL;
	}

	do_MLDSA_Keygen(adapter_handle);
	do_MLDSA_KAT(adapter_handle);

	ica_close_adapter(adapter_handle);

	return TEST_SUCC;
}
