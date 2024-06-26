TESTS = \
fips_test \
icastats_test.sh \
get_functionlist_test \
get_functionlist_cex_test \
get_version_test \
rng_test \
drbg_test \
drbg_birthdays_test.pl \
des_ecb_test \
des_cbc_test \
des_ctr_test \
des_cfb_test \
des_ofb_test \
tdes_ecb_test \
tdes_cbc_test \
tdes_ctr_test \
tdes_cfb_test \
tdes_ofb_test \
aes_ecb_test \
aes_cbc_test \
aes_ctr_test \
aes_cfb_test \
aes_ofb_test \
aes_xts_test \
aes_gcm_test \
aes_gcm_kma_test \
cbccs_test \
ccm_test \
cmac_test \
sha2_test.sh \
sha3_test.sh \
sha1_test \
sha256_test \
sha3_224_test \
sha3_256_test \
sha3_384_test \
sha3_512_test \
shake_128_test \
shake_256_test \
rsa_keygen1024_test.sh \
rsa_keygen2048_test.sh \
rsa_keygen3072_test.sh \
rsa_keygen4096_test.sh \
rsa_key_check_test \
rsa_test \
rsa_test_x \
ec_keygen1_test.sh \
ecdh1_test.sh \
ecdsa1_test.sh \
ec_keygen2_test.sh \
ecdh2_test.sh \
ecdsa2_test.sh \
eddsa_test \
x_test \
mp_test \
adapter_handle_test

if ICA_INTERNAL_TESTS
TESTS += \
${top_builddir}/src/internal_tests/ec_internal_test
endif

# disable OpenSSL CEX usage for all tests
OPENSSL_s390xcap ?= nocex

TEST_EXTENSIONS = .sh .pl
TESTS_ENVIRONMENT = export LD_LIBRARY_PATH=${builddir}/../src/.libs/:$$LD_LIBRARY_PATH \
			   PATH=${builddir}/../src/:$$PATH \
			   LIBICA_TESTDATA=${srcdir}/testdata/ \
			   OPENSSL_s390xcap=${OPENSSL_s390xcap};
AM_CFLAGS = @FLAGS@ -DNO_SW_FALLBACKS -I${srcdir}/../include/ -I${srcdir}/../src/include/
LDADD = @LIBS@ ${top_builddir}/src/.libs/libica.so -lcrypto -lpthread

get_functionlist_cex_test_SOURCES = get_functionlist_cex_test.c 
get_functionlist_cex_test_LDADD = @LIBS@ ${top_builddir}/src/.libs/libica-cex.so -lcrypto -lpthread

check_PROGRAMS = fips_test icastats_test get_functionlist_test \
get_version_test rng_test drbg_test drbg_birthdays_test \
des_ecb_test des_cbc_test des_ctr_test des_cfb_test des_ofb_test \
tdes_ecb_test tdes_cbc_test tdes_ctr_test tdes_cfb_test \
tdes_ofb_test aes_ecb_test \
aes_cbc_test aes_ctr_test aes_cfb_test aes_ofb_test aes_xts_test \
aes_gcm_test aes_gcm_kma_test cbccs_test ccm_test cmac_test sha_test \
sha1_test sha256_test sha3_224_test sha3_256_test sha3_384_test \
sha3_512_test shake_128_test shake_256_test rsa_keygen_test \
rsa_key_check_test rsa_test rsa_test_x ec_keygen_test ecdh_test ecdsa_test mp_test \
eddsa_test x_test get_functionlist_cex_test adapter_handle_test

EXTRA_DIST = testdata icastats_test.c.in

noinst_HEADERS = testcase.h rsa_test.h aes_gcm_test.h ecdsa_test.h eddsa_test.h

dist_check_SCRIPTS = ecdsa1_test.sh icastats_test.sh sha2_test.sh ecdh1_test.sh \
ecdsa2_test.sh ecdh2_test.sh drbg_birthdays_test.pl sha3_test.sh ec_keygen1_test.sh \
ec_keygen2_test.sh rsa_keygen2048_test.sh rsa_keygen1024_test.sh \
rsa_keygen4096_test.sh rsa_keygen3072_test.sh rsa_keygen_test.sh 

icastats_test.c: icastats_test.c.in
	@SED@   -e s!\@builddir\@!"@abs_top_builddir@/src/"!g < $< > $@-t
	mv $@-t $@

nodist_icastats_test_SOURCES = icastats_test.c
CLEANFILES = icastats_test.c
MAINTAINERCLEANFILES = Makefile.in
