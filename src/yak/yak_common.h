#pragma once

#include <openssl/evp.h>
// #include <openssl/kdf.h>
// #include <openssl/params.h>

#include <string>
/* 
#define OUT_LEN 90
#define HASH_SIZE 32
#define MD_FUNC EVP_sha256()
#define INFO "test"
#define INFO_LEN 4
*/
#include "crypto.h"
#include "mpc_ecc_core.h"

#include "logger.h"

namespace mpc {
    
struct yak_msg_t
{
  ecc_point_t pk;
  ecc_point_t eph;
  zk_dl_t eph_zkp;
  
  void convert(ub::converter_t &converter)
  {
    converter.convert(pk);
    converter.convert(eph);
    converter.convert(eph_zkp);
  }
};

struct yak_channel_info_t
{
  std::string my_addr, peer_addr;
};

error_t get_channel_info(const std::string channel_addr, yak_channel_info_t &info);

std::string sk_to_pk(std::string sk_hex);

std::string pk_to_addr(std::string public_key);

error_t check_pk_match(const ecc_point_t pk, const std::string peer_addr);

mem_t kdf(ecc_point_t p);

} //namespace mpc