// Check that the results of OpenSSL calls which return 1 for success, and
// 0 *or a negative value* for failure, are compared against 1.
//
// For these functions a negative value (e.g. -1 for an internal error, or -2
// for "operation not supported by this key type") is truthy, so the forms
//
//   if (EVP_DigestVerify (...))
//   if (EVP_DigestVerify (...) && ...)
//   if (EVP_DigestVerify (...) != 0)
//   if (!EVP_DigestVerify (...))          (as the failure test)
//   if (EVP_DigestVerify (...) == 0)      (as the failure test)
//
// treat an error as success.  Write `== 1` (or `!= 1` for the failure
// case) instead.  `> 0` and `<= 0` are also correct and are not flagged.
//
// The function list comes from the RETURN VALUES sections of the OpenSSL
// man pages (EVP_DigestSignInit(3), EVP_DigestVerifyInit(3),
// EVP_PKEY_sign(3), EVP_PKEY_verify(3), EVP_PKEY_check(3), X509_verify(3),
// X509_verify_cert(3), ...).  The EVP_DigestSign* functions are documented
// as returning 1/0, but EVP_DigestSign() and EVP_DigestSignFinal() pass the
// provider's result through, and we want sign and verify paths to be
// checked consistently.  Add new OpenSSL calls with the same return
// convention here.
//
// Only direct uses of the call are matched: a result stored in a variable
// and tested later is not tracked.
//
// This is run by `just coccinelle-check` and by tests/coccinelle.sh (part
// of `make check`); any output is a failure.  To run it alone:
//
//   spatch --very-quiet --dir . tests/coccinelle/openssl-retval.cocci

@ openssl_retval_fn @
identifier fn = {
  EVP_DigestSignInit, EVP_DigestSignInit_ex, EVP_DigestSignUpdate,
  EVP_DigestSignFinal, EVP_DigestSign,
  EVP_DigestVerifyInit, EVP_DigestVerifyInit_ex, EVP_DigestVerifyUpdate,
  EVP_DigestVerifyFinal, EVP_DigestVerify,
  EVP_VerifyFinal, EVP_VerifyFinal_ex,
  EVP_PKEY_sign_init, EVP_PKEY_sign_init_ex, EVP_PKEY_sign_init_ex2,
  EVP_PKEY_sign, EVP_PKEY_sign_message_init, EVP_PKEY_sign_message_update,
  EVP_PKEY_sign_message_final,
  EVP_PKEY_verify_init, EVP_PKEY_verify_init_ex, EVP_PKEY_verify_init_ex2,
  EVP_PKEY_verify, EVP_PKEY_verify_message_init,
  EVP_PKEY_verify_message_update, EVP_PKEY_verify_message_final,
  EVP_PKEY_verify_recover_init, EVP_PKEY_verify_recover_init_ex,
  EVP_PKEY_verify_recover_init_ex2, EVP_PKEY_verify_recover,
  EVP_PKEY_encrypt_init, EVP_PKEY_encrypt_init_ex, EVP_PKEY_encrypt,
  EVP_PKEY_decrypt_init, EVP_PKEY_decrypt_init_ex, EVP_PKEY_decrypt,
  EVP_PKEY_derive_init, EVP_PKEY_derive_init_ex, EVP_PKEY_derive_set_peer,
  EVP_PKEY_derive_set_peer_ex, EVP_PKEY_derive,
  EVP_PKEY_encapsulate_init, EVP_PKEY_encapsulate,
  EVP_PKEY_decapsulate_init, EVP_PKEY_decapsulate,
  EVP_PKEY_keygen_init, EVP_PKEY_keygen, EVP_PKEY_paramgen_init,
  EVP_PKEY_paramgen, EVP_PKEY_generate,
  EVP_PKEY_check, EVP_PKEY_public_check, EVP_PKEY_public_check_quick,
  EVP_PKEY_param_check, EVP_PKEY_param_check_quick, EVP_PKEY_private_check,
  EVP_PKEY_pairwise_check,
  EVP_PKEY_eq, EVP_PKEY_cmp, EVP_PKEY_parameters_eq, EVP_PKEY_cmp_parameters,
  EVP_PKEY_CTX_ctrl, EVP_PKEY_CTX_ctrl_str, EVP_PKEY_CTX_ctrl_uint64,
  X509_verify, X509_REQ_verify, X509_REQ_verify_ex, X509_CRL_verify,
  X509_verify_cert, X509_STORE_CTX_verify,
  DSA_do_verify, DSA_verify, ECDSA_do_verify, ECDSA_verify,
  OCSP_basic_verify
};
@@

fn(...)

@ openssl_retval_expr disable is_zero, isnt_zero, not_int1, not_int2 @
identifier openssl_retval_fn.fn;
expression list args;
expression E, E1, E2;
@@

(
* !fn(args)
|
* fn(args) == 0
|
* 0 == fn(args)
|
* fn(args) != 0
|
* 0 != fn(args)
|
* fn(args) && E
|
* E && fn(args)
|
* fn(args) || E
|
* E || fn(args)
|
* fn(args) ? E1 : E2
|
* g_assert (fn(args))
|
* g_return_if_fail (fn(args))
|
* g_return_val_if_fail (fn(args), E)
)

@ openssl_retval_stmt disable is_zero, isnt_zero, not_int1, not_int2 @
identifier openssl_retval_fn.fn;
expression list args;
statement S;
@@

(
* if (fn(args)) S
|
* while (fn(args)) S
)
