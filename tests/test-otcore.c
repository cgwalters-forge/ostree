/*
 * SPDX-License-Identifier: LGPL-2.0+
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <https://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "otcore.h"

#ifdef HAVE_OPENSSL
#include <openssl/dsa.h>
#include <openssl/ec.h>
#endif

static void
test_ed25519 (void)
{
  g_autoptr (GBytes) empty = g_bytes_new_static ("", 0);
  bool valid = false;
  g_autoptr (GError) error = NULL;
  if (otcore_validate_ed25519_signature (empty, empty, empty, &valid, &error))
    g_assert_not_reached ();
  g_assert (error != NULL);
  g_clear_error (&error);
}

#ifdef HAVE_OPENSSL
/* An ECDSA P-256 public key in DER SubjectPublicKeyInfo form, as produced by
 *   openssl ecparam -name prime256v1 -genkey -noout |
 *     openssl ec -pubout -outform DER
 * The spki mechanism takes any key d2i_PUBKEY() understands.
 */
static const guint8 ec_p256_pubkey[]
    = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        0x04, 0x80, 0x85, 0xe0, 0x67, 0xba, 0x0e, 0x92, 0xec, 0xa9, 0xf6, 0xfc, 0xa0,
        0x58, 0xc1, 0xda, 0x3f, 0x9b, 0xb3, 0x23, 0x59, 0x88, 0x93, 0x9d, 0x66, 0x36,
        0x30, 0x74, 0xb2, 0x7a, 0x9f, 0x4a, 0xf5, 0x53, 0x8d, 0x1b, 0xd8, 0xe6, 0xc7,
        0x82, 0x46, 0xa1, 0x65, 0x4d, 0x8a, 0x70, 0x2e, 0x71, 0xc3, 0x84, 0x8a, 0x20,
        0x3a, 0xc4, 0x18, 0x38, 0x9e, 0x24, 0x92, 0x99, 0x82, 0xcd, 0x80, 0x7f, 0xfd };

static void
test_spki (void)
{
  g_autoptr (GBytes) data = g_bytes_new_static ("some signed data", 16);
  g_autoptr (GBytes) pubkey = g_bytes_new_static (ec_p256_pubkey, sizeof (ec_p256_pubkey));
  /* Not a well-formed ECDSA signature, which openssl reports as an error
   * rather than as a signature mismatch.
   */
  g_autoptr (GBytes) signature = g_bytes_new_static ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32);
  bool valid = false;
  g_autoptr (GError) error = NULL;

  g_assert (otcore_validate_spki_signature (data, pubkey, signature, &valid, &error));
  g_assert_no_error (error);
  g_assert (!valid);
}

/* Key types whose openssl verification reports a malformed signature as an
 * error (a negative value) rather than as a mismatch (0).
 */
typedef struct
{
  const char *name;
  int type;
} SpkiKeyType;

static const SpkiKeyType spki_key_types[] = {
  { "ec", EVP_PKEY_EC },
  { "dsa", EVP_PKEY_DSA },
};

/* Returns NULL if this openssl cannot generate such a key, e.g. because the
 * algorithm is disabled by policy.
 */
static EVP_PKEY *
generate_spki_key (int type)
{
  EVP_PKEY *params = NULL;
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *kctx = NULL;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id (type, NULL);
  bool ok = pctx != NULL && EVP_PKEY_paramgen_init (pctx) == 1;

  if (ok && type == EVP_PKEY_EC)
    ok = EVP_PKEY_CTX_set_ec_paramgen_curve_nid (pctx, NID_X9_62_prime256v1) == 1;
  else if (ok && type == EVP_PKEY_DSA)
    ok = EVP_PKEY_CTX_set_dsa_paramgen_bits (pctx, 2048) == 1;

  if (ok && EVP_PKEY_paramgen (pctx, &params) == 1)
    kctx = EVP_PKEY_CTX_new (params, NULL);
  if (kctx == NULL || EVP_PKEY_keygen_init (kctx) != 1 || EVP_PKEY_keygen (kctx, &pkey) != 1)
    pkey = NULL;

  EVP_PKEY_CTX_free (kctx);
  EVP_PKEY_free (params);
  EVP_PKEY_CTX_free (pctx);
  return pkey;
}

static GBytes *
spki_sign (EVP_PKEY *pkey, GBytes *data)
{
  gsize data_size;
  const guint8 *data_buf = g_bytes_get_data (data, &data_size);
  size_t len = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  g_assert (ctx);

  g_assert (EVP_DigestSignInit (ctx, NULL, NULL, NULL, pkey) == 1);
  g_assert (EVP_DigestSign (ctx, NULL, &len, data_buf, data_size) == 1);
  g_autofree guchar *sig = g_malloc0 (len);
  g_assert (EVP_DigestSign (ctx, sig, &len, data_buf, data_size) == 1);
  EVP_MD_CTX_free (ctx);

  return g_bytes_new_take (g_steal_pointer (&sig), len);
}

static void
assert_spki_validity (GBytes *data, GBytes *pubkey, GBytes *signature, bool expected)
{
  bool valid = false;
  g_autoptr (GError) error = NULL;

  g_assert (otcore_validate_spki_signature (data, pubkey, signature, &valid, &error));
  g_assert_no_error (error);
  g_assert_cmpint (valid, ==, expected);
}

static void
test_spki_generated (gconstpointer user_data)
{
  const SpkiKeyType *key_type = user_data;
  EVP_PKEY *pkey = generate_spki_key (key_type->type);
  if (pkey == NULL)
    {
      g_test_skip ("openssl cannot generate this key type");
      return;
    }

  guchar *pubkey_buf = NULL;
  int pubkey_size = i2d_PUBKEY (pkey, &pubkey_buf);
  g_assert_cmpint (pubkey_size, >, 0);
  g_autoptr (GBytes) pubkey = g_bytes_new (pubkey_buf, pubkey_size);
  OPENSSL_free (pubkey_buf);

  g_autoptr (GBytes) data = g_bytes_new_static ("some signed data", 16);
  g_autoptr (GBytes) other_data = g_bytes_new_static ("other signed data", 17);
  g_autoptr (GBytes) signature = spki_sign (pkey, data);
  EVP_PKEY_free (pkey);

  /* A genuine signature is valid, but only for the data it was made over */
  assert_spki_validity (data, pubkey, signature, true);
  assert_spki_validity (other_data, pubkey, signature, false);

  /* Signatures that are not a well-formed DER structure, which openssl
   * reports as an error rather than as a signature mismatch.
   */
  g_autoptr (GBytes) empty = g_bytes_new_static ("", 0);
  assert_spki_validity (data, pubkey, empty, false);
  g_autoptr (GBytes) garbage = g_bytes_new_static ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32);
  assert_spki_validity (data, pubkey, garbage, false);
  gsize signature_size = g_bytes_get_size (signature);
  g_autoptr (GBytes) truncated = g_bytes_new_from_bytes (signature, 0, signature_size - 1);
  assert_spki_validity (data, pubkey, truncated, false);
}
#endif

static void
test_prepare_root_cmdline (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree char *target = NULL;
  static const char *notfound_cases[]
      = { "", "foo", "foo=bar baz  sometest", "xostree foo", "xostree=blah bar", NULL };
  for (const char **iter = notfound_cases; iter && *iter; iter++)
    {
      const char *tcase = *iter;
      g_assert (otcore_get_ostree_target (tcase, NULL, &target, &error));
      g_assert_no_error (error);
      g_assert (target == NULL);
    }

  // Test the default ostree=
  g_assert (
      otcore_get_ostree_target ("blah baz=blah ostree=/foo/bar somearg", NULL, &target, &error));
  g_assert_no_error (error);
  g_assert_cmpstr (target, ==, "/foo/bar");
  free (g_steal_pointer (&target));

  // Test android boot
  g_assert (otcore_get_ostree_target ("blah baz=blah androidboot.slot_suffix=_b somearg", NULL,
                                      &target, &error));
  g_assert_no_error (error);
  g_assert_cmpstr (target, ==, "/ostree/root.b");
  free (g_steal_pointer (&target));

  g_assert (otcore_get_ostree_target ("blah baz=blah androidboot.slot_suffix=_a somearg", NULL,
                                      &target, &error));
  g_assert_no_error (error);
  g_assert_cmpstr (target, ==, "/ostree/root.a");
  free (g_steal_pointer (&target));

  // And an expected failure to parse a "c" suffix
  g_assert (!otcore_get_ostree_target ("blah baz=blah androidboot.slot_suffix=_c somearg", NULL,
                                       &target, &error));
  g_assert (error);
  g_assert (target == NULL);
  g_clear_error (&error);

  // And non-A/B androidboot
  g_assert (otcore_get_ostree_target ("blah baz=blah androidboot.somethingelse somearg", NULL,
                                      &target, &error));
  g_assert_no_error (error);
  g_assert_cmpstr (target, ==, "/ostree/root.a");
  free (g_steal_pointer (&target));
}

static void
test_prepare_root_config (void)
{
  g_autoptr (GError) error = NULL;
  g_auto (GLnxTmpDir) tmpdir = {
    0,
  };
  g_assert (glnx_mkdtempat (AT_FDCWD, "/tmp/test-XXXXXX", 0777, &tmpdir, &error));
  g_assert_no_error (error);

  {
    g_autoptr (GKeyFile) config = NULL;
    g_auto (GStrv) keys = NULL;
    config = otcore_load_config (tmpdir.fd, "ostree/someconfig.conf", &error);
    g_assert (config);
    keys = g_key_file_get_groups (config, NULL);
    g_assert (keys && *keys == NULL);
  }

  g_assert (glnx_shutil_mkdir_p_at (tmpdir.fd, "usr/lib/ostree", 0755, NULL, NULL));
  g_assert (glnx_file_replace_contents_at (tmpdir.fd, "usr/lib/ostree/someconfig.conf",
                                           (guint8 *)"[foo]\nbar=baz", -1, 0, NULL, NULL));

  {
    g_autoptr (GKeyFile) config = NULL;
    g_auto (GStrv) keys = NULL;
    config = otcore_load_config (tmpdir.fd, "ostree/someconfig.conf", &error);
    g_assert (config);
    keys = g_key_file_get_groups (config, NULL);
    g_assert (keys);
    g_assert_cmpstr (*keys, ==, "foo");
  }

  g_assert (glnx_shutil_mkdir_p_at (tmpdir.fd, "etc/ostree", 0755, NULL, NULL));
  g_assert (glnx_file_replace_contents_at (tmpdir.fd, "usr/lib/ostree/someconfig.conf",
                                           (guint8 *)"[test]\nbar=baz", -1, 0, NULL, NULL));

  {
    g_autoptr (GKeyFile) config = NULL;
    g_auto (GStrv) keys = NULL;
    config = otcore_load_config (tmpdir.fd, "ostree/someconfig.conf", &error);
    g_assert (config);
    keys = g_key_file_get_groups (config, NULL);
    g_assert (keys);
    g_assert_cmpstr (*keys, ==, "test");
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  otcore_ed25519_init ();
  g_test_add_func ("/ed25519", test_ed25519);
#ifdef HAVE_OPENSSL
  otcore_spki_init ();
  g_test_add_func ("/spki", test_spki);
  for (gsize i = 0; i < G_N_ELEMENTS (spki_key_types); i++)
    {
      g_autofree char *path = g_strdup_printf ("/spki/generated/%s", spki_key_types[i].name);
      g_test_add_data_func (path, &spki_key_types[i], test_spki_generated);
    }
#endif
  g_test_add_func ("/prepare-root-cmdline", test_prepare_root_cmdline);
  g_test_add_func ("/prepare-root-config", test_prepare_root_config);
  return g_test_run ();
}
