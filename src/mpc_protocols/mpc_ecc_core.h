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
#include "mpc_core.h"

namespace mpc {

buf_t ZK_PAILLIER_P_non_interactive(const crypto::bn_t& N, const crypto::bn_t& phi_N, mem_t session_id);
bool ZK_PAILLIER_V_non_interactive(const crypto::bn_t& N, mem_t pi, mem_t session_id);


struct zk_paillier_zero_t
{
  bn_t e, z;

  void convert(ub::converter_t& converter)
  {
    converter.convert(e);
    converter.convert(z);
  }

  void p(const bn_t& N, const bn_t& c, mem_t session_id, uint8_t aux, const bn_t& r);
  bool v(const bn_t& N, const bn_t& c, mem_t session_id, uint8_t aux) const;
};

// added by XF Song, proving plaintext = m

//---------------- begin -----------------
struct zk_paillier_m_t 
{
  bn_t e, z, _r, _c; //_c = Enc(m, _r)

  void convert(ub::converter_t& converter)
  {
    converter.convert(e);
    converter.convert(z);
    converter.convert(_r);
    converter.convert(_c);
  }

  void p(const bn_t& N, const bn_t& c, const bn_t& m, mem_t session_id, uint8_t aux, const bn_t& r);
  bool v(const bn_t& N, const bn_t& c, const bn_t& m, mem_t session_id, uint8_t aux) const;
};

struct zk_paillier_mult_t
{
  bn_t e, c_d, c_db, c_1, c_2, f, z_1, z_2;

  void convert(ub::converter_t& converter)
  {
    converter.convert(e);
    converter.convert(c_d);
    converter.convert(c_db);
    converter.convert(z_1);
    converter.convert(z_2);
    converter.convert(f);
    converter.convert(c_1);
    converter.convert(c_2);
  }

  void p(const bn_t& N, const bn_t& c_a, const bn_t& c_b, const bn_t& c_c, mem_t session_id, uint8_t aux, 
                        const bn_t& a, const bn_t& b, const bn_t& c, const bn_t& r_a, const bn_t& r_b, const bn_t& r_c);
  bool v(const bn_t& N, const bn_t& c_a, const bn_t& c_b, const bn_t& c_c, mem_t session_id, uint8_t aux) const;
};

//----------------- end ------------------

struct zk_paillier_range_t 
{
  enum { t = 128 };
  struct info_t
  {
    bn_t a, b, c, d;
    void convert(ub::converter_t& converter)
    {
      converter.convert(a);
      converter.convert(b);
      converter.convert(c);
      converter.convert(d);
    }
  };

  info_t infos[t];
  buf128_t e;
  int u;

  void convert(ub::converter_t& converter)
  {
    converter.convert(u);
    converter.convert(e);
    converter.convert(infos);
  }

  void clear()
  {
    for (int i=0; i<t; i++) { infos[i].a = infos[i].b = infos[i].b = infos[i].d = 0; }
  }

  void p(bool threaded, const bn_t& q, const crypto::paillier_t& paillier, const bn_t& E, mem_t session_id, uint8_t aux, const bn_t& x, const bn_t& r);
  bool v(bool threaded, const bn_t& q, const bn_t& N, const bn_t& E, mem_t session_id, uint8_t aux) const;
};

struct zk_pdl_t
{
  bn_t c_r, c_rho, z;
  ecc_point_t R;
  zk_paillier_zero_t zk_paillier_zero;
  zk_paillier_range_t zk_paillier_range;

  void convert(ub::converter_t& converter)
  {
    converter.convert(c_r);
    converter.convert(c_rho);
    converter.convert(z);
    converter.convert(R);
    converter.convert(zk_paillier_zero);
    converter.convert(zk_paillier_range);
  }

  void p(ecurve_t curve, const ecc_point_t& Q, const bn_t& c_key, const crypto::paillier_t& paillier, mem_t session_id, uint8_t aux, const bn_t& r_key, const bn_t& x1);
  bool v(ecurve_t curve, const ecc_point_t& Q, const bn_t& c_key, const bn_t& N,                      mem_t session_id, uint8_t aux) const;
};

// added by XF Song
struct zk_pdl_mult_t
{
  ecc_point_t U;
  bn_t z, _z, t, k, w, 
       s, s_1, s_2, t_1, t_2;

  void convert(ub::converter_t& converter)
  {
    converter.convert(U);
    converter.convert(z);
    converter.convert(_z);
    converter.convert(t);
    converter.convert(k);
    converter.convert(w);
    converter.convert(s);
    converter.convert(s_1);
    converter.convert(s_2);
    converter.convert(t_1);
    converter.convert(t_2);
  }

  void p(ecurve_t curve, const ecc_point_t X, const bn_t c_1, const bn_t c_2, const crypto::paillier_t& paillier, const bn_t h_1, const bn_t h_2, const bn_t _N, mem_t session_id, uint8_t aux, 
         const bn_t x, const bn_t y, const bn_t r);
  bool v(ecurve_t curve, const ecc_point_t X, const bn_t N, const bn_t c_1, const bn_t c_2, const bn_t h_1, const bn_t h_2, const bn_t _N, mem_t session_id, uint8_t aux) const;
};



struct zk_dl_t
{
  bn_t e;
  bn_t u;
  void convert(ub::converter_t& converter)
  {
    converter.convert(e);
    converter.convert(u);
  }

  void p(ecurve_t curve, const ecc_point_t& Q, mem_t session_id, uint8_t aux, const bn_t& d);
  bool v(ecurve_t curve, const ecc_point_t& Q, mem_t session_id, uint8_t aux) const;
};

struct zk_ddh_t
{
  buf_t e_buf;
  bn_t u;
  void convert(ub::converter_t& converter)
  {
    converter.convert(e_buf);
    converter.convert(u);
  }

  void p(ecurve_t curve, const ecc_point_t& Q, const ecc_point_t& A, const ecc_point_t& B, const bn_t& w, mem_t session_id, uint8_t aux);
  bool v(ecurve_t curve, const ecc_point_t& Q, const ecc_point_t& A, const ecc_point_t& B, mem_t session_id, uint8_t aux) const;
};


struct zk_ec_affine_t
{
  bn_t e, z1, z2, z3;

  void convert(ub::converter_t& converter)
  {
    converter.convert(e);
    converter.convert(z1);
    converter.convert(z2);
    converter.convert(z3);
  }

  void p(const ecc_point_t& P, const ecc_point_t& U, const ecc_point_t& V, const ecc_point_t& U_tag, const ecc_point_t& V_tag, mem_t session_id, const bn_t& s, const bn_t& w, const bn_t& r_tag);
  bool v(const ecc_point_t& P, const ecc_point_t& U, const ecc_point_t& V, const ecc_point_t& U_tag, const ecc_point_t& V_tag, mem_t session_id) const;
};

class equality_test_t
{
public:
  void init(mem_t value) { value_hash = sha256_t::hash(value); }

  void convert(ub::converter_t& converter)
  {
    converter.convert(value_hash);
    converter.convert(t);
    converter.convert(U);
    converter.convert(V);
  }

  struct message1_t
  {
    ecc_point_t U, V, P;
    zk_dl_t zk_dl;

    void convert(ub::converter_t& converter)
    {
      converter.convert(U);
      converter.convert(V);
      converter.convert(P);
      converter.convert(zk_dl);
    }
  };
  struct message2_t
  {
    ecc_point_t U_tag, V_tag;
    zk_ec_affine_t zk_ec_affine;
    buf256_t hash;

    void convert(ub::converter_t& converter)
    {
      converter.convert(hash);
      converter.convert(U_tag);
      converter.convert(V_tag);
      converter.convert(zk_ec_affine);
    }
  };
  struct message3_t
  {
    ecc_point_t P_tag; // invalid in case of inequality
    void convert(ub::converter_t& converter)
    {
      converter.convert(P_tag);
    }
  };

  void peer1_step1(message1_t& out);
  error_t peer2_step1(const message1_t& in, message2_t& out);
  error_t peer1_step2(const message2_t& in, message3_t& out, bool& result);
  error_t peer2_step2(const message3_t& in, bool& result);

private:
  buf256_t value_hash;
  ecc_point_t U, V;
  bn_t t;
};


} //namespace mpc