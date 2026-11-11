// OpenSSL functions that return 1 for success and 0 or a negative value
// for failure.  Testing such a result for truthiness, or against 0, takes
// an error for success: that is how malformed signatures came to be
// accepted (https://github.com/ostreedev/ostree/pull/3665).  Require the
// result to be compared with 1 right at the call, which also rules out
// storing it in a variable to be tested loosely later.
//
// Functions that only ever return 0 or 1 (e.g. EVP_DigestUpdate) are not
// listed.  When starting to use a function of this family, add it here.

@call@
identifier fn = {
  EVP_DigestSignInit, EVP_DigestSignInit_ex, EVP_DigestSignUpdate,
  EVP_DigestSignFinal, EVP_DigestSign,
  EVP_DigestVerifyInit, EVP_DigestVerifyInit_ex, EVP_DigestVerifyUpdate,
  EVP_DigestVerifyFinal, EVP_DigestVerify,
  EVP_SignFinal, EVP_SignFinal_ex, EVP_VerifyFinal, EVP_VerifyFinal_ex,
  EVP_PKEY_sign_init, EVP_PKEY_sign, EVP_PKEY_verify_init, EVP_PKEY_verify,
  EVP_PKEY_verify_recover_init, EVP_PKEY_verify_recover,
  EVP_PKEY_encrypt_init, EVP_PKEY_encrypt, EVP_PKEY_decrypt_init,
  EVP_PKEY_decrypt, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer,
  EVP_PKEY_derive, EVP_PKEY_paramgen_init, EVP_PKEY_paramgen,
  EVP_PKEY_keygen_init, EVP_PKEY_keygen, EVP_PKEY_generate,
  EVP_PKEY_fromdata_init, EVP_PKEY_fromdata,
  EVP_PKEY_CTX_ctrl, EVP_PKEY_CTX_ctrl_str, EVP_PKEY_CTX_set_params,
  EVP_PKEY_CTX_set_signature_md, EVP_PKEY_CTX_set_rsa_padding,
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid, EVP_PKEY_CTX_set_dsa_paramgen_bits,
  EVP_PKEY_check, EVP_PKEY_public_check, EVP_PKEY_private_check,
  EVP_PKEY_param_check, EVP_PKEY_pairwise_check,
  EVP_PKEY_eq, EVP_PKEY_cmp, EVP_PKEY_parameters_eq, EVP_PKEY_cmp_parameters,
  X509_verify, X509_REQ_verify, X509_CRL_verify, X509_verify_cert,
  X509_check_host, X509_check_email, X509_check_ip, X509_check_ip_asc,
  PKCS7_verify, CMS_verify,
  RSA_verify, DSA_verify, DSA_do_verify, ECDSA_verify, ECDSA_do_verify,
  RAND_bytes, RAND_priv_bytes
};
@@
fn(...)

@ok@
identifier call.fn;
position p;
@@
(
  fn@p(...) == 1
|
  fn@p(...) != 1
)

@@
identifier call.fn;
position p != ok.p;
@@
* fn@p(...)
