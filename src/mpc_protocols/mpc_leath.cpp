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

#include "precompiled.h"
#include "mpc_core.h"
#include "mpc_ecdh.h"
#include "mpc_leath.h"

using namespace ub;
using namespace crypto;

namespace mpc {


bn_t eGCD(const bn_t N, const bn_t a, const bn_t b, bn_t &x, bn_t &y)
{
  if (b.is_zero())
  {
    x = bn_t(1);
    y = bn_t(0);
    return a;
  }
  else
  {
    bn_t d, rem;
    d = bn_t::div(a, b, &rem); // a = d * b + rem

    bn_t r = eGCD(N, b, rem, x, y); /* r = GCD(a, b) = GCD(b, a%b) */
    bn_t t = x;
    x = y;
    MODULO(N) y = t - d * y;
    return r;
  }
}

//------------------------ leath_create_paillier_t---------------------------------

error_t leath_create_paillier_t::peer1_step1(leath_client_share_t& client_share, mem_t session_id, message1_t& out)
{
  crypto::paillier_t paillier = client_share.paillier;
  out.N = paillier.get_N();
  out.pi_RN = ZK_PAILLIER_P_non_interactive(out.N, paillier.get_phi_N(), session_id);

  bn_t lambda, mu;
  bn_t r = eGCD(out.N, paillier.get_p(), paillier.get_q(), mu, lambda);
  assert( r == bn_t(1));

  bn_t r_1, r_2, r_3;
  r_1 = bn_t::rand(out.N);
  r_2 = bn_t::rand(out.N);
  r_3 = bn_t::rand(out.N);

  bn_t m1, m2;
  MODULO(out.N) m1 = mu * paillier.get_p();
  MODULO(out.N) m2 = lambda * paillier.get_q();

  // bn_t s, m;
  // MODULO(out.N) s = m1 + m2;
  // MODULO(out.N) m = m1 * m2;
  // assert( s == bn_t(1));

  out.c_1 = paillier.encrypt(m1, r_1);
  out.c_2 = paillier.encrypt(m2, r_2);
  client_share.c_1 = out.c_1;
  client_share.c_2 = out.c_2;

  out.c_3 = paillier.encrypt(0, r_3);
  // assert(paillier.decrypt(out.c_3).is_zero());

  out.zk_paillier_m.p(out.N, paillier.add_ciphers(out.c_1, out.c_2), bn_t(1), session_id, 1, r_1 * r_2); 
  out.zk_paillier_zero.p(out.N, out.c_3, session_id, 1, r_3);
  out.zk_paillier_mult.p(out.N, out.c_1, out.c_2, out.c_3, session_id, 1, m1, m2, bn_t(0), r_1, r_2, r_3);

  return 0;
}

error_t leath_create_paillier_t::peer2_step1(leath_server_share_t& server_share, mem_t session_id, int server_id, ecc_point_t pk, bn_t sk, const message1_t& in, message2_t& out)
{
  error_t rv = 0;

  int paillier_size = 1024; //get_safe_paillier_bits(curve);

  if (in.N.get_bits_count() < paillier_size) return rv = error(E_CRYPTO);

  if (!mpc::ZK_PAILLIER_V_non_interactive(in.N, in.pi_RN, session_id)) return rv = error(E_CRYPTO);
  // printf("in peer2_step1, after ZK_PAILLIER_V_non_interactive.v \n");

  crypto::paillier_t paillier; paillier.create_pub(in.N);

  
  if (!in.zk_paillier_zero.v(in.N, in.c_3, session_id, 1))  return rv = error(E_CRYPTO);
  // printf("in peer2_step1, after zk_paillier_zero.v \n");

  if (!in.zk_paillier_m.v(in.N, paillier.add_ciphers(in.c_1, in.c_2), bn_t(1), session_id, 1)) return rv = error(E_CRYPTO);
  // printf("in peer2_step1, after zk_paillier_m.v \n");

  if (!in.zk_paillier_mult.v(in.N, in.c_1, in.c_2, in.c_3, session_id, 1))  return rv = error(E_CRYPTO);
  // printf("in peer2_step1, after zk_paillier_mult.v \n");
  
 

// if all good, prepare return message
  ecurve_t curve = pk.get_curve();
  const bn_t& order = curve.order();
  
  bn_t r, r_r;
  r = bn_t::rand(in.N);
  r_r = bn_t::rand(in.N);

  out._c_i = paillier.add_ciphers(paillier.mul_scalar(in.c_1, sk), paillier.encrypt(r, r_r));

  out.pk_i = pk;
  out.zk_pdl_mult.p(curve, pk, in.c_1, out._c_i, paillier, server_share.h_1, server_share.h_2, server_share._N, session_id, 1, sk, r, r_r);

  // store locally
  server_share.N = in.N;
  server_share.c_1 = in.c_1;
  server_share.c_2 = in.c_2;
  int bits = curve.bits();
  if (server_id <= 0) return rv = error(E_BADARG);
  MODULO(in.N) server_share.keys_share = in.N - r * bn_t(2).pow(bits * (server_id - 1));
  
  return 0;
}

error_t leath_create_paillier_t::peer1_step2(leath_client_share_t& client_share, mem_t session_id, int server_id, const message2_t& in)
{
  error_t rv = 0;
  
  if (!in.zk_pdl_mult.v(in.pk_i.get_curve(), in.pk_i, client_share.paillier.get_N(), client_share.c_1, in._c_i, client_share.h_1, client_share.h_2, client_share._N, session_id, 1)) return rv = error(E_CRYPTO);
  // printf("in peer1_step2, after zk_pdl_mult.v \n");

  bn_t x_i = client_share.paillier.decrypt(in._c_i);

  if (server_id <= 0) return rv = error(E_BADARG);

  ecurve_t curve =  in.pk_i.get_curve();  if (!curve) return rv = ub::error(E_BADARG);
  int bits = curve.bits();

  // TODO: mayber return the share is better
  client_share.keys_share += x_i * bn_t(2).pow_mod(bn_t(bits * (server_id - 1)), client_share.paillier.get_N());
  
  return 0;
}

}