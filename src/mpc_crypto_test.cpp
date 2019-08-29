/*
 *     NOTICE
 *
 *     The blockchain-crypto-mpc software is licensed under a proprietary license or the GPL v.3. 
 *     If you choose to receive it under the GPL v.3 license, the following applies:
 *     Blockchain-crypto-mpc is a Multiparty Computation (MPC)-based cryptographic library for securing blockchain wallets and applications.
 *     
 *     Copyright (C) 2018, Unbound Tech Ltd. 
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 * 
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 * 
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "precompiled.h"
#include "mpc_crypto.h"
#include "mpc_ot.h"
#include "mpc_ecc_core.h"

#include "mpc_leath.h"
#include "leath_client.h"
#include "leath_server.h"
#include "leath.grpc.pb.h"
#include "leath.pb.h"
#include "leath_client_runner.h"
#include "leath_server_runner.h"

#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <csignal>
#include <unistd.h>

using namespace mpc;

extern "C" MPCCRYPTO_API int MPCCrypto_test();
extern "C" MPCCRYPTO_API int leath_client(int argc, char *argv[]);
extern "C" MPCCRYPTO_API int leath_server(int argc, char *argv[]);

static int share_to_buf(MPCCryptoShare *share, std::vector<uint8_t> &buf)
{
  int rv = 0;
  int size = 0;
  if (rv = MPCCrypto_shareToBuf(share, nullptr, &size))
    return rv;
  buf.resize(size);
  if (rv = MPCCrypto_shareToBuf(share, buf.data(), &size))
    return rv;
  return 0;
}

static int share_from_buf(const std::vector<uint8_t> &mem, MPCCryptoShare *&share)
{
  return MPCCrypto_shareFromBuf(mem.data(), (int)mem.size(), &share);
}

static int message_to_buf(MPCCryptoMessage *message, std::vector<uint8_t> &buf)
{
  int rv = 0;
  int size = 0;
  if (rv = MPCCrypto_messageToBuf(message, nullptr, &size))
    return rv;
  buf.resize(size);
  if (rv = MPCCrypto_messageToBuf(message, buf.data(), &size))
    return rv;
  return 0;
}

static int message_from_buf(const std::vector<uint8_t> &mem, MPCCryptoMessage *&message)
{
  return MPCCrypto_messageFromBuf(mem.data(), (int)mem.size(), &message);
}

static int context_to_buf(MPCCryptoContext *context, std::vector<uint8_t> &buf)
{
  int rv = 0;
  int size = 0;
  if (rv = MPCCrypto_contextToBuf(context, nullptr, &size))
    return rv;
  buf.resize(size);
  if (rv = MPCCrypto_contextToBuf(context, buf.data(), &size))
    return rv;
  return 0;
}

static int context_from_buf(const std::vector<uint8_t> &mem, MPCCryptoContext *&context)
{
  return MPCCrypto_contextFromBuf(mem.data(), (int)mem.size(), &context);
}

struct test_key_t
{
  MPCCryptoShare *client;
  MPCCryptoShare *server;

  test_key_t() : client(nullptr), server(nullptr) {}
  ~test_key_t()
  {
    MPCCrypto_freeShare(client);
    MPCCrypto_freeShare(server);
  }
};

struct test_context_t
{
  MPCCryptoContext *client;
  MPCCryptoContext *server;
  test_context_t() : client(nullptr), server(nullptr) {}
  ~test_context_t()
  {
    MPCCrypto_freeContext(client);
    MPCCrypto_freeContext(server);
  }
};

static int client_step(test_key_t &test_key, test_context_t &test_context, std::vector<uint8_t> &message_buf, bool &finished)
{
  int rv = 0;

  MPCCryptoMessage *in = nullptr;
  MPCCryptoMessage *out = nullptr;

  if (!message_buf.empty())
  {
    if (rv = message_from_buf(message_buf, in))
      return rv;
  }

  unsigned flags = 0;
  if (rv = MPCCrypto_step(test_context.client, in, &out, &flags))
    return rv;
  if (in)
    MPCCrypto_freeMessage(in);

  std::vector<uint8_t> context_buf;
  if (rv = context_to_buf(test_context.client, context_buf))
    return rv;
  MPCCrypto_freeContext(test_context.client);
  test_context.client = nullptr;
  if (rv = context_from_buf(context_buf, test_context.client))
    return rv;

  finished = (flags & mpc_protocol_finished) != 0;

  if (flags & mpc_share_changed)
  {
    MPCCrypto_freeShare(test_key.client);
    test_key.client = nullptr;
    if (rv = MPCCrypto_getShare(test_context.client, &test_key.client))
      return rv;
    std::vector<uint8_t> share_buf;
    if (rv = share_to_buf(test_key.client, share_buf))
      return rv;
    MPCCrypto_freeShare(test_key.client);
    test_key.client = nullptr;
    if (rv = share_from_buf(share_buf, test_key.client))
      return rv;
  }

  if (out)
  {
    if (rv = message_to_buf(out, message_buf))
      return rv;
    MPCCrypto_freeMessage(out);
  }
  else
    message_buf.clear();

  return rv;
}

uint64_t last_server_context_uid = 0;

static int server_step(test_key_t &test_key, test_context_t &test_context, std::vector<uint8_t> &message_buf, bool &finished)
{
  int rv = 0;

  MPCCryptoMessage *in = nullptr;
  MPCCryptoMessage *out = nullptr;

  if (rv = message_from_buf(message_buf, in))
    return rv;

  mpc_crypto_message_info_t message_info;
  if (rv = MPCCrypto_messageInfo(in, &message_info))
    return rv;

  unsigned flags = 0;
  if (rv = MPCCrypto_step(test_context.server, in, &out, &flags))
    return rv;
  if (in)
    MPCCrypto_freeMessage(in);

  std::vector<uint8_t> context_buf;
  if (rv = context_to_buf(test_context.server, context_buf))
    return rv;
  MPCCrypto_freeContext(test_context.server);
  test_context.server = nullptr;
  if (rv = context_from_buf(context_buf, test_context.server))
    return rv;

  finished = (flags & mpc_protocol_finished) != 0;

  if (flags & mpc_share_changed)
  {
    MPCCrypto_freeShare(test_key.server);
    test_key.server = nullptr;
    if (rv = MPCCrypto_getShare(test_context.server, &test_key.server))
      return rv;
    std::vector<uint8_t> share_buf;
    if (rv = share_to_buf(test_key.server, share_buf))
      return rv;
    MPCCrypto_freeShare(test_key.server);
    test_key.server = nullptr;
    if (rv = share_from_buf(share_buf, test_key.server))
      return rv;
  }

  if (out)
  {
    if (rv = message_to_buf(out, message_buf))
      return rv;
    MPCCrypto_freeMessage(out);
  }
  else
    message_buf.clear();

  return rv;
}

static int test_client_server(test_key_t &test_key, test_context_t &test_context)
{
  int rv = 0;

  bool client_finished = false;
  bool server_finished = false;

  std::vector<uint8_t> message_buf;

  while (!client_finished || !server_finished)
  {
    if (!client_finished)
    {
      if (rv = client_step(test_key, test_context, message_buf, client_finished))
        return rv;
    }

    if (message_buf.empty())
      break;

    if (!server_finished)
    {
      if (rv = server_step(test_key, test_context, message_buf, server_finished))
        return rv;
    }
  }

  return 0;
}

static int test_ecdsa_gen(test_key_t &test_key)
{
  int rv = 0;
  printf("test_ecdsa_gen...");

  test_context_t test_context;
  if (rv = MPCCrypto_initGenerateEcdsaKey(1, &test_context.client))
    return rv;
  if (rv = MPCCrypto_initGenerateEcdsaKey(2, &test_context.server))
    return rv;
  if (rv = test_client_server(test_key, test_context))
    return rv;

  printf(" ok\n");
  return rv;
}

static RSA *generate_rsa_key()
{
  BIGNUM *e = BN_new();
  BN_set_word(e, 65537);
  RSA *rsa_key = RSA_new();
  RSA_generate_key_ex(rsa_key, 2048, e, NULL);
  return rsa_key;
}

static std::vector<uint8_t> export_rsa_pub_key_info(RSA *rsa_key)
{
  std::vector<uint8_t> out;
  int out_size = i2d_RSA_PUBKEY(rsa_key, nullptr);
  if (out_size > 0)
  {
    out.resize(out_size);
    uint8_t *out_ptr = &out[0];
    i2d_RSA_PUBKEY(rsa_key, &out_ptr);
  }
  return out;
}

static std::vector<uint8_t> export_rsa_pkcs8_prv(RSA *rsa_key)
{
  std::vector<uint8_t> out;

  EVP_PKEY *evp_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(evp_key, rsa_key);

  PKCS8_PRIV_KEY_INFO *pkcs8 = EVP_PKEY2PKCS8(evp_key);
  int out_size = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, NULL);

  if (out_size > 0)
  {
    out.resize(out_size);
    uint8_t *out_ptr = &out[0];
    i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &out_ptr);
  }

  PKCS8_PRIV_KEY_INFO_free(pkcs8);
  EVP_PKEY_free(evp_key);

  return out;
}

static int test_ecdsa_backup(test_key_t &test_key)
{
  int rv = 0;
  printf("test_ecdsa_backup...");

  RSA *backup_rsa_key = generate_rsa_key();
  std::vector<uint8_t> backup_rsa_key_pub = export_rsa_pub_key_info(backup_rsa_key);
  std::vector<uint8_t> backup_rsa_key_prv = export_rsa_pkcs8_prv(backup_rsa_key);
  RSA_free(backup_rsa_key);

  test_context_t test_context;
  if (rv = MPCCrypto_initBackupEcdsaKey(1, test_key.client, backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), &test_context.client))
    return rv;
  if (rv = MPCCrypto_initBackupEcdsaKey(2, test_key.server, backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), &test_context.server))
    return rv;
  if (rv = test_client_server(test_key, test_context))
    return rv;

  int backup_size = 0;
  if (rv = MPCCrypto_getResultBackupEcdsaKey(test_context.client, nullptr, &backup_size))
    return rv;
  std::vector<uint8_t> backup(backup_size);
  if (rv = MPCCrypto_getResultBackupEcdsaKey(test_context.client, backup.data(), &backup_size))
    return rv;

  int pub_key_size = 0;
  if (rv = MPCCrypto_getEcdsaPublic(test_key.client, nullptr, &pub_key_size))
    return rv;
  std::vector<uint8_t> pub_ec_key(pub_key_size);
  if (rv = MPCCrypto_getEcdsaPublic(test_key.client, pub_ec_key.data(), &pub_key_size))
    return rv;

  if (rv = MPCCrypto_verifyEcdsaBackupKey(backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), pub_ec_key.data(), (int)pub_ec_key.size(), backup.data(), backup_size))
    return rv;

  int prv_key_size = 0;
  if (rv = MPCCrypto_restoreEcdsaKey(backup_rsa_key_prv.data(), (int)backup_rsa_key_prv.size(), pub_ec_key.data(), (int)pub_ec_key.size(), backup.data(), backup_size, nullptr, &prv_key_size))
    return rv;
  std::vector<uint8_t> prv_ec_key(prv_key_size);
  if (rv = MPCCrypto_restoreEcdsaKey(backup_rsa_key_prv.data(), (int)backup_rsa_key_prv.size(), pub_ec_key.data(), (int)pub_ec_key.size(), backup.data(), backup_size, prv_ec_key.data(), &prv_key_size))
    return rv;

  printf(" ok\n");
  return rv;
}

static int test_ecdsa_sign(test_key_t &test_key)
{
  int rv = 0;
  printf("test_ecdsa_sign...");

  char test[] = "123456";

  test_context_t test_context;
  if (rv = MPCCrypto_initEcdsaSign(1, test_key.client, (const uint8_t *)test, sizeof(test), 1, &test_context.client))
    return rv;
  if (rv = MPCCrypto_initEcdsaSign(2, test_key.server, (const uint8_t *)test, sizeof(test), 1, &test_context.server))
    return rv;

  if (rv = test_client_server(test_key, test_context))
    return rv;

  int sig_size = 0;
  if (rv = MPCCrypto_getResultEcdsaSign(test_context.client, nullptr, &sig_size))
    return rv;
  std::vector<uint8_t> sig(sig_size);
  if (rv = MPCCrypto_getResultEcdsaSign(test_context.client, sig.data(), &sig_size))
    return rv;

  int pub_key_size = 0;
  if (rv = MPCCrypto_getEcdsaPublic(test_key.client, nullptr, &pub_key_size))
    return rv;
  std::vector<uint8_t> pub_ec_key(pub_key_size);
  if (rv = MPCCrypto_getEcdsaPublic(test_key.client, pub_ec_key.data(), &pub_key_size))
    return rv;

  if (rv = MPCCrypto_verifyEcdsa(pub_ec_key.data(), (int)pub_ec_key.size(), (const uint8_t *)test, sizeof(test), sig.data(), sig_size))
    return rv;

  printf(" ok\n");
  return rv;
}

static int test_eddsa_gen(test_key_t &test_key)
{
  int rv = 0;
  printf("test_eddsa_gen...");

  test_context_t test_context;
  if (rv = MPCCrypto_initGenerateEddsaKey(1, &test_context.client))
    return rv;
  if (rv = MPCCrypto_initGenerateEddsaKey(2, &test_context.server))
    return rv;

  if (rv = test_client_server(test_key, test_context))
    return rv;
  printf(" ok\n");
  return rv;
}

static int test_eddsa_backup(test_key_t &test_key)
{
  int rv = 0;
  printf("test_eddsa_backup...");

  RSA *backup_rsa_key = generate_rsa_key();
  std::vector<uint8_t> backup_rsa_key_pub = export_rsa_pub_key_info(backup_rsa_key);
  std::vector<uint8_t> backup_rsa_key_prv = export_rsa_pkcs8_prv(backup_rsa_key);
  RSA_free(backup_rsa_key);

  test_context_t test_context;
  if (rv = MPCCrypto_initBackupEddsaKey(1, test_key.client, backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), &test_context.client))
    return rv;
  if (rv = MPCCrypto_initBackupEddsaKey(2, test_key.server, backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), &test_context.server))
    return rv;
  if (rv = test_client_server(test_key, test_context))
    return rv;

  int backup_size = 0;
  if (rv = MPCCrypto_getResultBackupEddsaKey(test_context.client, nullptr, &backup_size))
    return rv;
  std::vector<uint8_t> backup(backup_size);
  if (rv = MPCCrypto_getResultBackupEddsaKey(test_context.client, backup.data(), &backup_size))
    return rv;

  uint8_t pub_eddsa_key[32];
  if (rv = MPCCrypto_getEddsaPublic(test_key.client, pub_eddsa_key))
    return rv;

  if (rv = MPCCrypto_verifyEddsaBackupKey(backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), pub_eddsa_key, backup.data(), backup_size))
    return rv;
  uint8_t prv_eeddsa_key[32];
  if (rv = MPCCrypto_restoreEddsaKey(backup_rsa_key_prv.data(), (int)backup_rsa_key_prv.size(), pub_eddsa_key, backup.data(), backup_size, prv_eeddsa_key))
    return rv;

  printf(" ok\n");
  return rv;
}

static int test_eddsa_sign(test_key_t &test_key)
{
  int rv = 0;
  printf("test_eddsa_sign...");
  uint8_t sig[64];

  char test[] = "123456";

  test_context_t test_context;
  if (rv = MPCCrypto_initEddsaSign(1, test_key.client, (const uint8_t *)test, sizeof(test), 1, &test_context.client))
    return rv;
  if (rv = MPCCrypto_initEddsaSign(2, test_key.server, (const uint8_t *)test, sizeof(test), 1, &test_context.server))
    return rv;

  if (rv = test_client_server(test_key, test_context))
    return rv;

  if (rv = MPCCrypto_getResultEddsaSign(test_context.client, sig))
    return rv;

  uint8_t pub_key[32];
  if (rv = MPCCrypto_getEddsaPublic(test_key.client, pub_key))
    return rv;
  if (rv = MPCCrypto_verifyEddsa(pub_key, (const uint8_t *)test, sizeof(test), sig))
    return rv;

  printf(" ok\n");
  return rv;
}

int test_refresh(test_key_t &test_key)
{
  int rv = 0;
  printf("test_refresh...");

  test_context_t test_context;
  if (rv = MPCCrypto_initRefreshKey(1, test_key.client, &test_context.client))
    return rv;
  if (rv = MPCCrypto_initRefreshKey(2, test_key.server, &test_context.server))
    return rv;

  if (rv = test_client_server(test_key, test_context))
    return rv;

  printf(" ok\n");
  return rv;
}

static int test_generic_secret_gen(test_key_t &test_key)
{
  int rv = 0;
  printf("test_generic_secret_gen...");

  test_context_t test_context;
  if (rv = MPCCrypto_initGenerateGenericSecret(1, 256, &test_context.client))
    return rv;
  if (rv = MPCCrypto_initGenerateGenericSecret(2, 256, &test_context.server))
    return rv;

  if (rv = test_client_server(test_key, test_context))
    return rv;
  printf(" ok\n");
  return rv;
}

static int test_generic_secret_import(test_key_t &test_key)
{
  int rv = 0;
  printf("test_generic_secret_import...");
  std::vector<uint8_t> value(32);
  RAND_bytes(value.data(), 32);

  test_context_t test_context;
  if (rv = MPCCrypto_initImportGenericSecret(1, value.data(), (int)value.size(), &test_context.client))
    return rv;
  if (rv = MPCCrypto_initImportGenericSecret(2, value.data(), (int)value.size(), &test_context.server))
    return rv;

  if (rv = test_client_server(test_key, test_context))
    return rv;
  printf(" ok\n");
  return rv;
}

static int test_bip_serialize(test_key_t &key, const std::string &test)
{
  int rv = 0;

  int ser_size = 0;
  if (rv = MPCCrypto_serializePubBIP32(key.client, nullptr, &ser_size))
    return rv;
  char *s = new char[ser_size + 1];
  if (rv = MPCCrypto_serializePubBIP32(key.client, s, &ser_size))
    return rv;

  if (s != test)
    rv = MPC_E_CRYPTO;
  delete[] s;
  return rv;
}

static int hex2int(char input)
{
  if (input >= '0' && input <= '9')
    return input - '0';
  if (input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if (input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  return -1;
}

static std::vector<uint8_t> hex2bin(const std::string &src)
{
  int dst_size = (int)src.length() / 2;
  std::vector<uint8_t> dst(dst_size);
  for (int i = 0; i < dst_size; i++)
    dst[i] = hex2int(src[i * 2]) * 16 + hex2int(src[i * 2 + 1]);
  return dst;
}

static int test_bip_master(test_key_t &key, const std::string &seed, const std::string &test)
{
  printf("test_bip_master...");

  int rv = 0;
  std::vector<uint8_t> seed_key = hex2bin(seed);

  test_context_t import;
  if (rv = MPCCrypto_initImportGenericSecret(1, seed_key.data(), (int)seed_key.size(), &import.client))
    return rv;
  if (rv = MPCCrypto_initImportGenericSecret(2, seed_key.data(), (int)seed_key.size(), &import.server))
    return rv;
  test_key_t test_seed_key;
  if (rv = test_client_server(test_seed_key, import))
    return rv;

  test_context_t test_context;
  if (rv = MPCCrypto_initDeriveBIP32(1, test_seed_key.client, 0, 0, &test_context.client))
    return rv;
  if (rv = MPCCrypto_initDeriveBIP32(2, test_seed_key.server, 0, 0, &test_context.server))
    return rv;
  if (rv = test_client_server(test_seed_key, test_context))
    return rv;

  if (rv = MPCCrypto_getResultDeriveBIP32(test_context.client, &key.client))
    return rv;
  if (rv = MPCCrypto_getResultDeriveBIP32(test_context.server, &key.server))
    return rv;

  //if (rv = test_refresh(bip.key)) return rv;
  if (rv = test_bip_serialize(key, test))
    return rv;
  //if (rv = test_ecdsa_sign(key)) return rv;
  printf(" ok\n");
  return rv;
}

static int test_bip_derive(test_key_t &src, bool hardened, unsigned index, test_key_t &dst, const std::string &test)
{
  printf("test_bip_derive...");
  int rv = 0;

  test_context_t test_context;
  if (rv = MPCCrypto_initDeriveBIP32(1, src.client, hardened ? 1 : 0, index, &test_context.client))
    return rv;
  if (rv = MPCCrypto_initDeriveBIP32(2, src.server, hardened ? 1 : 0, index, &test_context.server))
    return rv;
  if (rv = test_client_server(src, test_context))
    return rv;
  if (rv = MPCCrypto_getResultDeriveBIP32(test_context.client, &dst.client))
    return rv;
  if (rv = MPCCrypto_getResultDeriveBIP32(test_context.server, &dst.server))
    return rv;

  //if (rv = test_refresh(dst.key)) return rv;
  if (rv = test_bip_serialize(dst, test))
    return rv;
  //if (rv = test_ecdsa_sign(dst)) return rv;
  printf(" ok\n");
  return rv;
}

static int test_bip()
{
  int rv = 0;

  {
    test_key_t m, m_0H, m_0H_1, m_0H_1_2H, m_0H_1_2H_2, m_0H_1_2H_2_1000000000;
    if (rv = test_bip_master(m, "000102030405060708090a0b0c0d0e0f", "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"))
      return rv;
    if (rv = test_bip_derive(m, true, 0, m_0H, "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"))
      return rv;
    if (rv = test_bip_derive(m_0H, false, 1, m_0H_1, "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"))
      return rv;
    if (rv = test_bip_derive(m_0H_1, true, 2, m_0H_1_2H, "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"))
      return rv;
    if (rv = test_bip_derive(m_0H_1_2H, false, 2, m_0H_1_2H_2, "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"))
      return rv;
    if (rv = test_bip_derive(m_0H_1_2H_2, false, 1000000000, m_0H_1_2H_2_1000000000, "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"))
      return rv;
  }

  {
    test_key_t m, m_0, m_0_2147483647H, m_0_2147483647H_1, m_0_2147483647H_1_2147483646H, m_0_2147483647H_1_2147483646H_2;
    if (rv = test_bip_master(m, "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"))
      return rv;
    if (rv = test_bip_derive(m, false, 0, m_0, "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"))
      return rv;
    if (rv = test_bip_derive(m_0, true, 2147483647, m_0_2147483647H, "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"))
      return rv;
    if (rv = test_bip_derive(m_0_2147483647H, false, 1, m_0_2147483647H_1, "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"))
      return rv;
    if (rv = test_bip_derive(m_0_2147483647H_1, true, 2147483646, m_0_2147483647H_1_2147483646H, "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"))
      return rv;
    if (rv = test_bip_derive(m_0_2147483647H_1_2147483646H, false, 2, m_0_2147483647H_1_2147483646H_2, "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"))
      return rv;
  }

  {
    test_key_t m, m_0;
    if (rv = test_bip_master(m, "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be", "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"))
      return rv;
    if (rv = test_bip_derive(m, true, 0, m_0, "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"))
      return rv;
  }

  return rv;
}

// added by XF Song

static int test_paillier()
{
  crypto::paillier_t p_1024, p_2048, p_3027;

  p_1024.generate(1024, true);
  p_2048.generate(2048, true);
  p_3027.generate(3027, true);
  // p_4096.generate(4096, true);
  // p_5120.generate(5120, true);
  // p_6144.generate(6144, true);

  // p_1024
  crypto::bn_t N = p_1024.get_N(), N2 = N * N;

  u_int count = 30;
  crypto::bn_t m[count], c[count];

  //--------1024---------
  for (int i = 0; i < count; i++)
  {
    m[i] = crypto::bn_t::rand(N);
  }
  std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    c[i] = p_1024.encrypt(m[i]);
  }
  std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
  double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_1024 encryption: %f ms \n", duration / count);

  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    m[i] = p_1024.decrypt(c[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_1024 decryption: %f ms \n", duration / count);

  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    MODULO(N2) c[i] = c[i].pow(m[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_1024 raw pow: %f ms \n", duration / count);

  // -------2048---------
  N = p_2048.get_N();
  N2 = N * N;
  for (int i = 0; i < count; i++)
  {
    m[i] = crypto::bn_t::rand(N);
  }

  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    c[i] = p_2048.encrypt(m[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_2048 encryption: %f ms \n", duration / count);

  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    m[i] = p_2048.decrypt(c[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_2048 encryption: %f ms \n", duration / count);

  
  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    MODULO(N2) c[i] = c[i].pow(m[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_2048 raw pow: %f ms \n", duration / count);

  //----------3027-----------
  N = p_3027.get_N();
  N = N * N;
  for (int i = 0; i < count; i++)
  {
    m[i] = crypto::bn_t::rand(N);
  }
  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    c[i] = p_3027.encrypt(m[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_3072 encryption: %f ms \n", duration / count);

  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    m[i] = p_3027.decrypt(c[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_3072 decryption: %f ms \n", duration / count);

  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    MODULO(N2) c[i] = c[i].pow(m[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_3027 raw pow: %f ms \n", duration / count);
/*
  // p_4096
  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    c[i] = p_4096.encrypt(m[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_4096 encryption: %f ms \n", duration / (count));

  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    m[i] = p_4096.decrypt(c[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_4096 decryption: %f ms \n", duration / (count));

  // p_5120
  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    c[i] = p_5120.encrypt(m[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_5120 encryption: %f ms \n", duration / (count));

  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    m[i] = p_5120.decrypt(c[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_5120 decryption: %f ms \n", duration / (count));

  // p_6144
  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    c[i] = p_6144.encrypt(m[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_6144 encryption: %f ms \n", duration / (count));

  begin = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < count; i++)
  {
    m[i] = p_6144.decrypt(c[i]);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("p_6144 decryption: %f ms \n", duration / (count));
*/
  return 0;
}

// added by XF Song
static int test_leath_create_paillier()
{
  error_t rv;

  // client's input
  crypto::paillier_t p_2048, _p;
  p_2048.generate(2048, true);
  _p.generate(2048, true);

  // auxulary value
  bn_t _N, h1, h2;
  _N = _p.get_N();
  h1 = bn_t::rand(_N);
  h2 = bn_t::rand(_N);

  mpc::leath_client_share_t c_share;
  mpc::leath_server_share_t s_share;
  s_share.h_1 = c_share.h_1 = h1;
  s_share.h_2 = c_share.h_2 = h2;
  s_share._N = c_share._N = _N;
  s_share.server_id = 1; // TODO: just for test now
  c_share.paillier = p_2048;

  //printf("%s\n\n", c_share.paillier.get_N().to_string().c_str());

  // curve information
  ecc_point_t G;
  bn_t order;
  ecurve_t curve = ecurve_t::find(NID_secp256k1);
  if (!curve)
    return rv = ub::error(E_BADARG);
  G = curve.generator();
  order = curve.order();

  // server1's input
  ecc_point_t pk1;
  bn_t sk1 = bn_t::rand(order);
  pk1 = G * sk1;

  // server2's input
  ecc_point_t pk2;
  bn_t sk2 = bn_t::rand(order);
  pk2 = G * sk2;

  mpc::leath_create_paillier_t setup;
  mpc::leath_create_paillier_t::message1_t msg1;
  mpc::leath_create_paillier_t::message2_t msg2;

  //printf("before steps. \n\n");
  // => msg1
  if (rv = setup.peer1_step1(c_share, mem_t::from_string("session1"), msg1))
    return ub::error(E_BADARG);

  //  mpc::leath_create_paillier_t::message1_t fuck;
  //  buf_t msg1_buf = ub::convert(msg1);
  //  ub::convert(fuck, ub::mem_t(msg1_buf.data(), msg1_buf.size()) );

  //printf("before peer2_step1. \n\n");
  // msg1 => msg2
  if (rv = setup.peer2_step1(s_share, mem_t::from_string("session1"), s_share.server_id, pk1, sk1, msg1, msg2))
    return ub::error(E_BADARG);

  // printf("before peer1_step2. \n\n");
  // msg2 <=
  if (rv = setup.peer1_step2(c_share, mem_t::from_string("session1"), s_share.server_id, msg2))
    return ub::error(E_BADARG);
  return 0;
}

static int test_ecurve()
{
  error_t rv = 0;
  ecurve_t curve = ecurve_t::find(NID_secp256k1);
  if (!curve)
    return rv = ub::error(E_BADARG);
  ecc_generator_point_t G = curve.generator();
  bn_t order = curve.order();
  int bits = curve.bits();
  printf("bits: %d bits \n", bits);
}

static int test_leath_share_reconstruct()
{
  error_t rv = 0;
  std::string server_path = "test", client_path = "test";

  mpc::LeathServer server(server_path, 1);
  mpc::LeathClient client(client_path, 1, 1024);

  mpc::leath_setup_message1_t msg1;
  mpc::leath_setup_message2_t msg2;

  rv = client.leath_setup_peer1_step1(ub::mem_t::from_string("setup_session"), msg1);
  // printf("after leath_setup_peer1_step1. \n\n");

  assert(rv == 0);

  // ecc_point_t G;
  // bn_t order;
  // ecurve_t curve = ecurve_t::find(NID_secp256k1);
  // if (!curve)
  //     return ub::error(E_BADARG);
  // G = curve.generator();
  // order = curve.order();
  // ecc_point_t pk1;
  // bn_t sk1 = bn_t::rand(order);
  // pk1 = G * sk1;

  //---------------------------------
  rv = server.leath_setup_peer2_step1(ub::mem_t::from_string("setup_session"), 0, msg1, msg2);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step2(ub::mem_t::from_string("setup_session"), 0, msg2);
  assert(rv == 0);
  return 0;
}

static int test_leath_client_server()
{

  error_t rv = 0;
  std::string server_path = "test-server", client_path = "test-client";

  mpc::LeathServer server0(server_path + "_0", 0), server1(server_path + "_1", 1);
  mpc::LeathClient client(client_path, 2, 3072);


  rv = client.leath_setup_paillier_generation();
  assert(rv == 0);

  mpc::leath_setup_message1_t client_setup_msg1;
  mpc::leath_setup_message2_t server0_setup_msg2, server1_setup_msg2;
  mpc::leath_setup_message3_t server0_setup_msg3, server1_setup_msg3;

  rv = client.leath_setup_peer1_step1(ub::mem_t::from_string("setup_session"), client_setup_msg1);
  assert(rv == 0);

std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();

  //---------------------------------
  rv = server0.leath_setup_peer2_step1(ub::mem_t::from_string("setup_session"), 0, client_setup_msg1, server0_setup_msg2);
  assert(rv == 0);

  rv = server1.leath_setup_peer2_step1(ub::mem_t::from_string("setup_session"), 1, client_setup_msg1, server1_setup_msg2);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step2(ub::mem_t::from_string("setup_session"), 0, server0_setup_msg2);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step2(ub::mem_t::from_string("setup_session"), 1, server1_setup_msg2);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), 0, server0_setup_msg3);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), 1, server1_setup_msg3);
  assert(rv == 0);

  rv = server0.leath_setup_peer2_step2(ub::mem_t::from_string("setup_session"), 0, server0_setup_msg3);
  assert(rv == 0);

  rv = server1.leath_setup_peer2_step2(ub::mem_t::from_string("setup_session"), 1, server1_setup_msg3);
  assert(rv == 0);

  //-----------------check mac generation------------------
  bn_t tmp, N;
  bn_t p = client.client_share.paillier.get_p();
  bn_t q = client.client_share.paillier.get_q();
  N = p * q;
  int bits = server0.server_share.pk.get_curve().bits();

  MODULO(client.client_share.N)
  tmp = client.client_share.mac_key - server0.server_share.mac_key_share - server1.server_share.mac_key_share;
  assert(tmp == 0);

  MODULO(client.client_share.N)
  tmp = client.client_share.keys_share + server0.server_share.keys_share + server1.server_share.keys_share;
  assert(tmp % p == 0);
  // FIXME: Sometimes bug happens for 1024-bits paillier, because q may less than sk2||sk1 in some case !
  assert(server1.server_share.sk * bn_t(2).pow(bits) + server0.server_share.sk == tmp % q);

  tmp = tmp - (server1.server_share.sk * bn_t(2).pow(bits) + server0.server_share.sk) * client.client_share.paillier.decrypt(client.client_share.c_1);
  assert(tmp % N == 0);

std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for setup without network & encoding:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


begin = std::chrono::high_resolution_clock::now();
  //----------------check share and reconstruction---------

  std::vector<leath_maced_share_with_VID_t> shares;
  leath_maced_share_with_VID_t server0_share;
  leath_maced_share_with_VID_t server1_share;

  // vid = 1, raw_data = 678;
  rv = client.leath_share_peer1_step1(ub::mem_t::from_string("share_session"), 1, bn_t(789), shares);
  // logger::log(logger::INFO)<< bn_t(789).to_string() <<std::endl;
  assert(rv == 0);
  bn_t raw_data_ = 0;
  MODULO(p)
  raw_data_ = shares[0].maced_share.share + shares[1].maced_share.share - client.client_share.keys_share;
  assert(raw_data_ == bn_t(789));

  server0.leath_share_peer2_step1(ub::mem_t::from_string("share_session"), shares[0], server0_share);
  server1.leath_share_peer2_step1(ub::mem_t::from_string("share_session"), shares[1], server1_share);

  MODULO(p)
  raw_data_ = server0_share.maced_share.share + server1_share.maced_share.share;
  assert(raw_data_ == bn_t(789));

end = std::chrono::high_resolution_clock::now();
duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for share without network & encoding:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


  //----------------data reconstruction--------------------

begin = std::chrono::high_resolution_clock::now();

  leath_maced_share_t cipher_share_s0, cipher_share_s1;
  std::vector<leath_maced_share_t> cipher_share_vector;
  bn_t data = 0;

  server0.leath_reconstruct_peer2_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_s0);
  server1.leath_reconstruct_peer2_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_s1);
  cipher_share_vector.push_back(cipher_share_s0);
  cipher_share_vector.push_back(cipher_share_s1);

  raw_data_ = 0;
  raw_data_ = client.client_share.paillier.decrypt(cipher_share_vector[0].share * cipher_share_vector[1].share);

  MODULO(p)
  raw_data_ = raw_data_ - 0;
  logger::log(logger::INFO) << "reconstruct raw_data: " << raw_data_.to_string() << std::endl;
  assert(raw_data_ == bn_t(789));

  // above is all good ...

  rv = client.leath_reconstruct_peer1_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_vector, data);

  assert(rv == 0); // error!

  logger::log(logger::INFO) << "reconstruct data: " << data.to_string() << std::endl;
  assert(data == bn_t(789));

end = std::chrono::high_resolution_clock::now();
duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for reconstruction without network & encoding:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


  std::ifstream is("/home/jason/Desktop/blockchain-crypto-mpc/src/test.txt", std::ios::binary);
  std::stringstream ifs_stream;
  ifs_stream << is.rdbuf();
  logger::log(logger::INFO) << ifs_stream.str() << std::endl;



//   is.seekg(0, is.end);
//   int length = is.tellg();
//   is.seekg(0, is.beg);
// logger::log(logger::INFO) << length << std::endl;
//   // allocate memory:
//   char *buffer = new char[length];

//   mem_t m_buf((const_byte_ptr)buffer, length);

//   // read data as a block:
//   is.read(buffer, length);

//   is.close();

//   std::stringstream stream;
//   stream << is.rdbuf();

// logger::log(logger::INFO) << stream.str() << std::endl;


// logger::log(logger::INFO) << buf_t(mem_t((const_byte_ptr)buffer, length)).to_string() << std::endl;
//   // print content:
//   std::cout.write(buffer, length);

  std::string client_share_path = "/home/jason/Desktop/blockchain-crypto-mpc/src/test.txt";

  std::ofstream client_share_out(client_share_path.c_str());
  client_share_out << "hi";
  return 0;
}

static int test_leath_client_3server()
{


  error_t rv = 0;
  std::string server_path = "test-server", client_path = "test-client";

  mpc::LeathServer server0(server_path + "_0", 0), server1(server_path + "_1", 1), server2(server_path + "_2", 2);
  mpc::LeathClient client(client_path, 3, 2048);

  rv = client.leath_setup_paillier_generation();
  assert(rv == 0);

std::chrono::high_resolution_clock::time_point t0 = std::chrono::high_resolution_clock::now();


  mpc::leath_setup_message1_t client_setup_msg1;
  mpc::leath_setup_message2_t server0_setup_msg2, server1_setup_msg2, server2_setup_msg2;
  mpc::leath_setup_message3_t server0_setup_msg3, server1_setup_msg3, server2_setup_msg3;

  rv = client.leath_setup_peer1_step1(ub::mem_t::from_string("setup_session"), client_setup_msg1);
  assert(rv == 0);



  //---------------------------------
  rv = server0.leath_setup_peer2_step1(ub::mem_t::from_string("setup_session"), 0, client_setup_msg1, server0_setup_msg2);
  assert(rv == 0);


  rv = server1.leath_setup_peer2_step1(ub::mem_t::from_string("setup_session"), 1, client_setup_msg1, server1_setup_msg2);
  assert(rv == 0);

  rv = server2.leath_setup_peer2_step1(ub::mem_t::from_string("setup_session"), 2, client_setup_msg1, server2_setup_msg2);
  assert(rv == 0);

std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();


std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

  rv = client.leath_setup_peer1_step2(ub::mem_t::from_string("setup_session"), 0, server0_setup_msg2);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step2(ub::mem_t::from_string("setup_session"), 1, server1_setup_msg2);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step2(ub::mem_t::from_string("setup_session"), 2, server2_setup_msg2);
  assert(rv == 0);


  rv = client.leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), 0, server0_setup_msg3);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), 1, server1_setup_msg3);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), 2, server2_setup_msg3);
  assert(rv == 0);



  rv = server0.leath_setup_peer2_step2(ub::mem_t::from_string("setup_session"), 0, server0_setup_msg3);
  assert(rv == 0);


  rv = server1.leath_setup_peer2_step2(ub::mem_t::from_string("setup_session"), 1, server1_setup_msg3);
  assert(rv == 0);

  rv = server2.leath_setup_peer2_step2(ub::mem_t::from_string("setup_session"), 2, server2_setup_msg3);
  assert(rv == 0);

std::chrono::high_resolution_clock::time_point t3 = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2 + t1 - t0).count();
logger::log(logger::INFO)<< "Time for setup without network & encoding:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


t0 = std::chrono::high_resolution_clock::now();
  //----------------check share and reconstruction---------

  std::vector<leath_maced_share_with_VID_t> shares;
  leath_maced_share_with_VID_t server0_share;
  leath_maced_share_with_VID_t server1_share;
  leath_maced_share_with_VID_t server2_share;

  rv = client.leath_share_peer1_step1(ub::mem_t::from_string("share_session"), 1, bn_t(789), shares);



  server0.leath_share_peer2_step1(ub::mem_t::from_string("share_session"), shares[0], server0_share);
  server1.leath_share_peer2_step1(ub::mem_t::from_string("share_session"), shares[1], server1_share);
  server2.leath_share_peer2_step1(ub::mem_t::from_string("share_session"), shares[2], server2_share);

t1 = std::chrono::high_resolution_clock::now();
duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
logger::log(logger::INFO)<< "Time for share without network & encoding:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


  //----------------data reconstruction--------------------


  leath_maced_share_t cipher_share_s0, cipher_share_s1, cipher_share_s2;
  std::vector<leath_maced_share_t> cipher_share_vector;
  bn_t data = 0;

t0 = std::chrono::high_resolution_clock::now();

  server0.leath_reconstruct_peer2_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_s0);
  server1.leath_reconstruct_peer2_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_s1);
  server2.leath_reconstruct_peer2_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_s2);


  cipher_share_vector.push_back(cipher_share_s0);
  cipher_share_vector.push_back(cipher_share_s1);
  cipher_share_vector.push_back(cipher_share_s2);


  rv = client.leath_reconstruct_peer1_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_vector, data);

t1 = std::chrono::high_resolution_clock::now();

  assert(rv == 0); // error!

  logger::log(logger::INFO) << "reconstruct data: " << data.to_string() << std::endl;
  assert(data == bn_t(789));

duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
logger::log(logger::INFO)<< "Time for reconstruction without network & encoding:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

  return 0;
}



static int test_leath_client_4server()
{


  error_t rv = 0;
  std::string server_path = "test-server", client_path = "test-client";

  mpc::LeathServer server0(server_path + "_0", 0), server1(server_path + "_1", 1), server2(server_path + "_2", 2), server3(server_path + "_3", 3);
  mpc::LeathClient client(client_path, 4, 3072);

  rv = client.leath_setup_paillier_generation();
  assert(rv == 0);

std::chrono::high_resolution_clock::time_point t0 = std::chrono::high_resolution_clock::now();


  mpc::leath_setup_message1_t client_setup_msg1;
  mpc::leath_setup_message2_t server0_setup_msg2, server1_setup_msg2, server2_setup_msg2, server3_setup_msg2;
  mpc::leath_setup_message3_t server0_setup_msg3, server1_setup_msg3, server2_setup_msg3, server3_setup_msg3;

  rv = client.leath_setup_peer1_step1(ub::mem_t::from_string("setup_session"), client_setup_msg1);
  assert(rv == 0);



  //---------------------------------
  rv = server0.leath_setup_peer2_step1(ub::mem_t::from_string("setup_session"), 0, client_setup_msg1, server0_setup_msg2);
  assert(rv == 0);


  rv = server1.leath_setup_peer2_step1(ub::mem_t::from_string("setup_session"), 1, client_setup_msg1, server1_setup_msg2);
  assert(rv == 0);

  rv = server2.leath_setup_peer2_step1(ub::mem_t::from_string("setup_session"), 2, client_setup_msg1, server2_setup_msg2);
  assert(rv == 0);

  rv = server3.leath_setup_peer2_step1(ub::mem_t::from_string("setup_session"), 3, client_setup_msg1, server3_setup_msg2);
  assert(rv == 0);

std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();


std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

  rv = client.leath_setup_peer1_step2(ub::mem_t::from_string("setup_session"), 0, server0_setup_msg2);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step2(ub::mem_t::from_string("setup_session"), 1, server1_setup_msg2);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step2(ub::mem_t::from_string("setup_session"), 2, server2_setup_msg2);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step2(ub::mem_t::from_string("setup_session"), 3, server3_setup_msg2);
  assert(rv == 0);


  rv = client.leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), 0, server0_setup_msg3);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), 1, server1_setup_msg3);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), 2, server2_setup_msg3);
  assert(rv == 0);

  rv = client.leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), 3, server3_setup_msg3);
  assert(rv == 0);



  rv = server0.leath_setup_peer2_step2(ub::mem_t::from_string("setup_session"), 0, server0_setup_msg3);
  assert(rv == 0);


  rv = server1.leath_setup_peer2_step2(ub::mem_t::from_string("setup_session"), 1, server1_setup_msg3);
  assert(rv == 0);

  rv = server2.leath_setup_peer2_step2(ub::mem_t::from_string("setup_session"), 2, server2_setup_msg3);
  assert(rv == 0);

  rv = server3.leath_setup_peer2_step2(ub::mem_t::from_string("setup_session"), 3, server3_setup_msg3);
  assert(rv == 0);

std::chrono::high_resolution_clock::time_point t3 = std::chrono::high_resolution_clock::now();

double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2 + t1 - t0).count();
logger::log(logger::INFO)<< "Time for setup without network & encoding:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


t0 = std::chrono::high_resolution_clock::now();
  //----------------check share and reconstruction---------

  std::vector<leath_maced_share_with_VID_t> shares;
  leath_maced_share_with_VID_t server0_share;
  leath_maced_share_with_VID_t server1_share;
  leath_maced_share_with_VID_t server2_share;
  leath_maced_share_with_VID_t server3_share;

  rv = client.leath_share_peer1_step1(ub::mem_t::from_string("share_session"), 1, bn_t(789), shares);



  server0.leath_share_peer2_step1(ub::mem_t::from_string("share_session"), shares[0], server0_share);
  server1.leath_share_peer2_step1(ub::mem_t::from_string("share_session"), shares[1], server1_share);
  server2.leath_share_peer2_step1(ub::mem_t::from_string("share_session"), shares[2], server2_share);
  server3.leath_share_peer2_step1(ub::mem_t::from_string("share_session"), shares[3], server3_share);

t1 = std::chrono::high_resolution_clock::now();

duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
logger::log(logger::INFO)<< "Time for share without network & encoding:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


  //----------------data reconstruction--------------------


  leath_maced_share_t cipher_share_s0, cipher_share_s1, cipher_share_s2, cipher_share_s3;
  std::vector<leath_maced_share_t> cipher_share_vector;
  bn_t data = 0;

t0 = std::chrono::high_resolution_clock::now();

  server0.leath_reconstruct_peer2_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_s0);
  server1.leath_reconstruct_peer2_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_s1);
  server2.leath_reconstruct_peer2_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_s2);
  server3.leath_reconstruct_peer2_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_s3);


  cipher_share_vector.push_back(cipher_share_s0);
  cipher_share_vector.push_back(cipher_share_s1);
  cipher_share_vector.push_back(cipher_share_s2);
  cipher_share_vector.push_back(cipher_share_s3);


  rv = client.leath_reconstruct_peer1_step1(ub::mem_t::from_string("reconstruction_session"), 1, cipher_share_vector, data);

t1 = std::chrono::high_resolution_clock::now();

  assert(rv == 0); // error!

  logger::log(logger::INFO) << "reconstruct data: " << data.to_string() << std::endl;
  assert(data == bn_t(789));

duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
logger::log(logger::INFO)<< "Time for reconstruction without network & encoding:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

  return 0;
}



//-----------------leath rpc client and server--------------------------
grpc::Server *server_ptr__ = NULL;

void exit_handler(int signal)
{
  std::cout << "INFO: "
            << "\nExiting ... " << std::endl;

  if (server_ptr__)
  {
    server_ptr__->Shutdown();
  }
};

static int test_leath_server_rpc()
{
  std::signal(SIGTERM, exit_handler);
  std::signal(SIGINT, exit_handler);
  std::signal(SIGQUIT, exit_handler);

  mpc::run_leath_server("0.0.0.0:7788", 0, "", &server_ptr__);

  logger::log(logger::INFO) << "Done." << std::endl;
  return 0;
}

static int test_leath_client_rpc()
{

  std::unique_ptr<mpc::LeathClientRunner> client_runner;

  std::vector<std::string> addresses;
  addresses.push_back("localhost:7788");
  addresses.push_back("localhost:7788");

  client_runner.reset(new mpc::LeathClientRunner(addresses, "", 1024));
  // std::cout << "INFO:" << "before setup." << std::endl;
  client_runner->setup();

  logger::log(logger::INFO) << "Done." << std::endl;

  return 0;
}

namespace mpc
{
extern int zk_paillier_range_time;
}

MPCCRYPTO_API int leath_client(int argc, char *argv[])
{

  std::unique_ptr<mpc::LeathClientRunner> client_runner;

  std::vector<std::string> addresses;
   addresses.push_back("localhost:7700");
   addresses.push_back("localhost:7701");
  // addresses.push_back("localhost:7702");
  // addresses.push_back("localhost:7703");
  // addresses.push_back("localhost:7704");
  // addresses.push_back("localhost:7705");
  //addresses.push_back("35.173.122.111:70000");
  //addresses.push_back("13.57.233.63:70001");
  //addresses.push_back("18.191.105.102:70002");
  //addresses.push_back("54.237.157.39:70003");
  //addresses.push_back("13.58.41.77:70004");
  //addresses.push_back("13.56.249.230:70005");

  int bits = 2048;
  int share_counter = 0, reconstruction_counter = 0;

  bool is_share = false;
  bool is_reconstruction = false;

  opterr = 0;
  int c;
  int setup_way = 1;
  
  while ((c = getopt(argc, argv, "i:s:r:b:")) != -1)
    switch (c)
    {
    case 'b':
      bits = atoi(optarg);
      client_runner.reset(new mpc::LeathClientRunner(addresses, "test-client", bits));
      break;

    case 'i':
      setup_way = atoi(optarg);
      //logger::log(logger::INFO) << "hi." << std::endl;
      client_runner->pre_setup();
      //logger::log(logger::INFO) << "hh." << std::endl;
      if (setup_way == 1) client_runner->setup();
      if (setup_way == 2) client_runner->simple_setup();
      break;

    case 's':
      is_share = true;
      share_counter = atoi(optarg);
      break;

    case 'r':
      //TODO:
      is_reconstruction = true;
      reconstruction_counter = atoi(optarg);
      break;

    default:
      exit(-1);
    }

  error_t rv = 0;

  if(is_share){
    rv = client_runner->share_benchmark(0, share_counter);
    sleep(2);
  }

  if (is_reconstruction) {
    rv = client_runner->bulk_reconstruct(0,  reconstruction_counter);
  }
  logger::log(logger::INFO) << "Done." << std::endl;


  return 0;
}

MPCCRYPTO_API int leath_server(int argc, char *argv[])
{
  opterr = 0;
  int c;

  bool async_search = true;

  std::string server_address;
  uint8_t server_id;
  logger::log(logger::INFO) << "Before server setup..." << std::endl;
  while ((c = getopt(argc, argv, "i:s:r:a:")) != -1)
    switch (c)
    {
    case 'i':
      server_id = std::stoi(std::string(optarg));
      break;
    case 's':
      //TODO:
      break;

    case 'r':
      //TODO:
      break;

    case 'a':
      server_address = std::string(optarg);
      break;

    // case '?':
    //     if (optopt == 'i')
    //         fprintf (stderr, "Option -%c requires an argument.\n", optopt);
    //     else if (isprint (optopt))
    //         fprintf (stderr, "Unknown option `-%c'.\n", optopt);
    //     else
    //         fprintf (stderr,
    //                  "Unknown option character `\\x%x'.\n",
    //                  optopt);
    //     return 1;
    default:
      logger::log(logger::INFO) << "Before server setup..." << std::endl;
      exit(-1);
    }

  mpc::run_leath_server(server_address, server_id, "test-server", &server_ptr__);

  std::cout << "INFO:"
            << "Done." << std::endl;

  return 0;
}

static int test_zk() 
{
  zk_DF_nonneg_t zk, zk_2;
  crypto::paillier_t p_1024, _p_1024;
  int bits = 2048;
  p_1024.generate(bits, true);
  _p_1024.generate(bits + 2, true);

logger::log(logger::INFO) << "key generation done." <<std::endl;

  bn_t G, H, alpha, _N;
  _N = _p_1024.get_N();
  G = bn_t::rand(_N);
  H = bn_t::rand(_N);
  alpha = bn_t::rand(_N);


  MODULO(_N) G = G * G;
  MODULO(_N) H = G.pow(alpha);

logger::log(logger::INFO) << "before com." <<std::endl;


  bn_t msg, r_1, com;
  msg = 123;
  r_1 = bn_t::rand(_N);
logger::log(logger::INFO) << "before commit." <<std::endl;

  MODULO(_N) com = G.pow(msg) * H.pow(r_1);

logger::log(logger::INFO) << "before zk prove." <<std::endl;


// ----------------zk_DF_nonneg_t------------------

//   zk.p(com, G, H, _N, bits, ub::mem_t::from_string("test"), 1, msg, r_1);
//   // ub::convert(zk_2, zk);
//   buf_t msg1_buf = ub::convert(zk);
//   ub::convert(zk_2, ub::mem_t(msg1_buf.data(), msg1_buf.size()) );

//   // logger::log(logger::INFO) << "prove done." <<std::endl;
//   bool error = zk.v(com, G, H, _N, ub::mem_t::from_string("test"), 1);
//   if (!error) 
//     logger::log(logger::ERROR) << "fucked" <<std::endl;
//   else {
//     logger::log(logger::INFO) << "good" <<std::endl;
//   }



// //--------------zk_DF_Paillier_equal_t--------------
//   zk_DF_Paillier_equal_t zk_3;
  //  bn_t ciphertext, r_enc;
  //  r_enc = bn_t::rand(p_1024.get_N());
  //  ciphertext = p_1024.encrypt(msg, r_enc);

//   zk_3.p(com, ciphertext, G, H, _N, p_1024, bits, ub::mem_t::from_string("test"), 1, msg, r_enc, r_1);

//   error = zk_3.v(com, ciphertext, G, H, _N, p_1024.get_N(), bits, ub::mem_t::from_string("test"), 1);

//   if (!error) 
//     logger::log(logger::ERROR) << "fucked" <<std::endl;
//   else {
//     logger::log(logger::INFO) << "good" <<std::endl;
//   }


// //------------------zk_DF_com_range_t------------------
//   zk_DF_com_range_t zk_4;

//   bn_t a = 2, b = p_1024.get_N() - 1;

//   zk_4.p(com, a, b, G, H, _N, bits, ub::mem_t::from_string("test"), 1, msg, r_1);

//   error = zk_4.v(com, a, b, G, H, _N, bits, ub::mem_t::from_string("test"), 1);

//   if (!error) 
//     logger::log(logger::ERROR) << "fucked" <<std::endl;
//   else {
//     logger::log(logger::INFO) << "good" <<std::endl;
//   }


logger::log(logger::INFO) << "\n\n\n" <<std::endl;
//------------------zk_DF_Paillier_range_t------------------

  bn_t ciphertext, r_enc;
  r_enc = bn_t::rand(p_1024.get_N());

  bn_t m_1, m_2;
  eGCD(p_1024.get_N(), p_1024.get_p(), p_1024.get_q(), m_1, m_2);

  ciphertext = p_1024.encrypt(m_1 * p_1024.get_p(), r_enc);

  bn_t  a = 2; 
  bn_t  b = p_1024.get_N() - 1;


  double d1 = 0.0, d2 = 0.0;
  int size = 0;

  for(int i = 0; i < 10; i++) {
    zk_DF_Paillier_range_t zk_5;
    std::chrono::high_resolution_clock::time_point t0 = std::chrono::high_resolution_clock::now();

      zk_5.p(ciphertext, a, b, G, H, _N, p_1024, bits, ub::mem_t::from_string("test"), 1, msg, r_enc);

    std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

      bool error = zk_5.v(ciphertext, a, b, G, H, _N, p_1024.get_N(), bits, ub::mem_t::from_string("test"), 1);

    std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
    
    d1 += (double)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    d2 += (double)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();


    buf_t msg2_buf = ub::convert(zk_5);
    size += msg2_buf.size();
    
    if (!error){
      logger::log(logger::ERROR) << "fucked" <<std::endl;
    }
  }


  logger::log(logger::INFO) << "time for zk_DF_Paillier_range_t prove:"  << d1 / 10.0 << " us" <<std::endl;
  logger::log(logger::INFO) << "time for zk_DF_Paillier_range_t verify:"  << d2 / 10.0 << " us" <<std::endl;

  logger::log(logger::INFO) << "proof size:"  << size / 10.0 << " bytes" <<std::endl;
/* 
  d1 = 0.0, d2 = 0.0, size = 0;
  for(int i = 0; i < 10; i++) {
    zk_DF_Paillier_range_t zk_5;
    std::chrono::high_resolution_clock::time_point t0 = std::chrono::high_resolution_clock::now();

      zk_5.p(ciphertext, a, b, G, H, _N, p_1024, bits, ub::mem_t::from_string("test"), 1, msg, r_enc);

    std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

      bool error = zk_5.v(ciphertext, a, b, G, H, _N, p_1024.get_N(), bits, ub::mem_t::from_string("test"), 1);

    std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
    
    d1 += (double)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    d2 += (double)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();


    buf_t msg2_buf = ub::convert(zk_5);
    size += msg2_buf.size();
    
    if (!error){
      logger::log(logger::ERROR) << "fucked" <<std::endl;
    }
  }


  logger::log(logger::INFO) << "time for zk_DF_Paillier_range_t prove:"  << d1/10.0 << " us" <<std::endl;
  logger::log(logger::INFO) << "time for zk_DF_Paillier_range_t verify:"  << d2 / 10.0 << " us" <<std::endl;

  logger::log(logger::INFO) <<  "proof size:"  << size/10.0 << " bytes" <<std::endl;
*/

  //ub::convert(zk_5, ub::mem_t(msg2_buf.data(), msg2_buf.size()) );
  /* 2048:
  [INFO] - time for zk_DF_Paillier_range_t prove:243466 us
  [INFO] - time for zk_DF_Paillier_range_t verify:132670 us
  [INFO] - proof size:12237 bytes

  3072:
  [INFO] - time for zk_DF_Paillier_range_t prove:770705 us
  [INFO] - time for zk_DF_Paillier_range_t verify:389848 us
  [INFO] - proof size:17870 bytes
  */


}

MPCCRYPTO_API int MPCCrypto_test()
{
  int rv = 0;
  /*
  test_key_t eddsa_key;
  if (rv = test_eddsa_gen(eddsa_key)) return rv;
  if (rv = test_eddsa_backup(eddsa_key)) return rv;
  for (int i=0; i<3; i++)
  {
    if (rv = test_eddsa_sign(eddsa_key)) return rv;
    if (rv = test_refresh(eddsa_key)) return rv;
  }

  */
  /*   test_key_t ecdsa_key;
  if (rv = test_ecdsa_gen(ecdsa_key)) return rv;

  uint64_t t = ub::read_timer_ms();
  for (int i=0; i<10; i++)
  {
    if (rv = test_ecdsa_sign(ecdsa_key)) return rv;
  }
  t = ub::read_timer_ms() - t; */

  // test_paillier();
  test_zk();

  // rv = test_paillier();
  // assert(rv == 0);
  // logger::log(logger::INFO) << "ALL GOOD !" << std::endl;
  /*
  if (rv = test_ecdsa_backup(ecdsa_key)) return rv;
  for (int i=0; i<3; i++)
  {
    if (rv = test_ecdsa_sign(ecdsa_key)) return rv;
    if (rv = test_refresh(ecdsa_key)) return rv;
  }


  if (rv = test_bip()) return rv;

  test_key_t secret_key1; if (rv = test_generic_secret_import(secret_key1)) return rv;
  test_key_t secret_key2; if (rv = test_generic_secret_gen(secret_key2)) return rv;
  for (int i = 0; i<3; i++)
  {
    if (rv = test_refresh(secret_key2)) return rv;
  }
  */
  //printf("\nAll tests successfully finished. 10 Signatures took %d ms\n", int(t));
  return rv;
}
