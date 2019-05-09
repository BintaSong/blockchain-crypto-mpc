/*
 *     NOTICE
 *
 *     The blockchain-crypto-mpc software is licensed under a proprietary license or the GPL v.3. 
 *     If you choose to receive it under the GPL v.3 license, the following applies:
 *     Blockchain-crypto-mpc is a Multiparty Computation (MPC)-based cryptographic library for securing blockchain wallets and applications.
 *     
 *     Copyright (C) 2018, Unbound Tech Ltd. 
 *
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

#pragma once
#include "crypto.h"
#include "mpc_ecc_core.h"

#include "logger.h"

namespace mpc
{

int get_safe_paillier_bits(ecurve_t curve);

bn_t eGCD(const bn_t N, const bn_t a, const bn_t b, bn_t &x, bn_t &y);

struct leath_client_share_t
{
  bn_t h_1, h_2, _N, N, N2, p, q;
  bn_t x_1, x_2, r_1, r_2, c_1, c_2, keys_share, mac_key;
  crypto::paillier_t paillier;

  void convert(ub::converter_t &converter)
  {
    converter.convert(h_1);
    converter.convert(h_2);
    converter.convert(_N);
    converter.convert(N);
    converter.convert(N2);
    converter.convert(p);
    converter.convert(q);
    converter.convert(x_1);
    converter.convert(x_2);
    converter.convert(r_1);
    converter.convert(r_2);
    converter.convert(c_1);
    converter.convert(c_2);
    converter.convert(keys_share);
    converter.convert(mac_key);
    converter.convert(paillier);
  }
};

struct leath_server_share_t
{
  int server_id;
  bn_t h_1, h_2, _N;
  bn_t c_1, c_2, N, N2;
  ecc_point_t pk;
  bn_t sk, keys_share, mac_key_share;

  void convert(ub::converter_t &converter)
  {
    converter.convert(server_id);
    converter.convert(h_1);
    converter.convert(h_2);
    converter.convert(c_1);
    converter.convert(c_2);
    converter.convert(_N);
    converter.convert(N);
    converter.convert(N2);
    converter.convert(pk);
    converter.convert(sk);
    converter.convert(keys_share);
    converter.convert(mac_key_share);
  }
};

struct leath_create_paillier_t
{
  struct message1_t
  {
    bn_t N, c_1, c_2, c_3;
    buf_t pi_RN;
    zk_paillier_m_t zk_paillier_m;
    zk_paillier_zero_t zk_paillier_zero;
    zk_paillier_mult_t zk_paillier_mult;

    void convert(ub::converter_t &converter)
    {
      converter.convert(N);
      converter.convert(c_1);
      converter.convert(c_2);
      converter.convert(c_3);
      converter.convert(pi_RN);
      converter.convert(zk_paillier_m);
      converter.convert(zk_paillier_zero);
      converter.convert(zk_paillier_mult);
    }
  };

  struct message2_t
  {
    bn_t _c_i; // _c_i = c_1 ^ sk_i + r mod N
    ecc_point_t pk_i;
    zk_pdl_mult_t zk_pdl_mult;

    void convert(ub::converter_t &converter)
    {
      converter.convert(_c_i);
      converter.convert(pk_i);
      converter.convert(zk_pdl_mult);
    }
  };

  void convert(ub::converter_t &converter)
  {
  }

  error_t peer1_step1(leath_client_share_t &client_share, mem_t session_id, message1_t &out);
  error_t peer2_step1(leath_server_share_t &server_share, mem_t session_id, int server_id, ecc_point_t pk, bn_t sk, const message1_t &in, message2_t &out);
  error_t peer1_step2(leath_client_share_t &client_share, mem_t session_id, int server_id, const message2_t &in);
};

struct leath_setup_message1_t
{
  bn_t N, c_1, c_2, c_3;
  buf_t pi_RN;
  bn_t h_1, h_2, _N;
  zk_paillier_m_t zk_paillier_m;
  zk_paillier_zero_t zk_paillier_zero;
  zk_paillier_mult_t zk_paillier_mult;

  void convert(ub::converter_t &converter)
  {
    converter.convert(N);
    converter.convert(c_1);
    converter.convert(c_2);
    converter.convert(c_3);
    converter.convert(pi_RN);
    converter.convert(h_1);
    converter.convert(h_2);
    converter.convert(_N);
    converter.convert(zk_paillier_m);
    converter.convert(zk_paillier_zero);
    converter.convert(zk_paillier_mult);
  }
};

struct leath_setup_message2_t
{
  bn_t _c_i; // _c_i = c_1 ^ sk_i + r mod N
  ecc_point_t pk_i;
  zk_pdl_mult_t zk_pdl_mult;

  void convert(ub::converter_t &converter)
  {
    converter.convert(_c_i);
    converter.convert(pk_i);
    converter.convert(zk_pdl_mult);
  }
};


struct leath_setup_message3_t
{
  bn_t mac_key_share;

  void convert(ub::converter_t &converter)
  {
    converter.convert(mac_key_share);
  }
};

struct leath_maced_share_t
{
  //uint64_t val_id;
  bn_t share, mac_share;

  void convert(ub::converter_t &converter)
  {
    //converter.convert(val_id);
    converter.convert(share);
    converter.convert(mac_share);
  }
};

struct leath_maced_share_with_VID_t
{
  uint64_t val_id;
  leath_maced_share_t maced_share;

  void convert(ub::converter_t &converter)
  {
    converter.convert(val_id);
    converter.convert(maced_share);
  }
};


// error_t peer1_step1(leath_client_share_t &client_share, mem_t session_id, leath_setup_message1_t &out);
// error_t peer2_step1(leath_server_share_t &server_share, mem_t session_id, int server_id, ecc_point_t pk, bn_t sk, const leath_setup_message1_t &in, leath_setup_message2_t &out);
// error_t peer1_step2(leath_client_share_t &client_share, mem_t session_id, int server_id, const leath_setup_message2_t &in);

} //namespace mpc