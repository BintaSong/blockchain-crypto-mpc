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
#include "mpc_ecc_core.h"


using namespace ub;
using namespace crypto;


#include "python2.7/Python.h"

//std::mutex RS_mutx_;

void RS(bn_t n, bn_t *ret) {

    Py_Initialize();

    std::string path = "./src/mpc_protocols";
    std::string chdir_cmd = std::string("sys.path.append(\"") + path + "\")";
    const char* cstr_cmd = chdir_cmd.c_str();
    PyRun_SimpleString("import sys");
    PyRun_SimpleString(cstr_cmd);

    PyObject* moduleName = PyString_FromString("RS"); 
    PyObject* pModule = PyImport_Import(moduleName);
/*     if (!pModule) 
    {
        logger::log(logger::INFO)<< "Time for paillier key _N generation:"  << d32  << " us" <<std::endl;
        return ;
    }*/

    PyObject* pv = PyObject_GetAttrString(pModule, "get_rs");
   /* if (!pv || !PyCallable_Check(pv))  
    {
        std::cout << "[ERROR] Can't find funftion (test_add)" << std::endl;
        return ;
    }
 */
    //
    PyObject* args = PyTuple_New(1);  
    PyObject* arg1 = PyInt_FromString((char*) n.to_string().c_str(), 0, 10); 
    PyTuple_SetItem(args, 0, arg1);
    // PyTuple_SetItem(args, 1, arg2);

    //
    PyObject* pRet = PyObject_CallObject(pv, args);

    if (pRet)  
    {   
      PyObject* item = PyList_GetItem(pRet, 2);
      assert(item != NULL);
      std::string result = PyString_AS_STRING(item);

      for(int i = 0; i < 4; i++) {
        PyObject* item = PyList_GetItem(pRet, i);
        assert(item != NULL);
       
        std::string result = PyString_AS_STRING(item);
        ret[i] = bn_t::from_string(result.c_str());
        // mpc::logger::log(mpc::logger::INFO) << "[RS]:" << ret[i].to_string() << std::endl;
      }
    }
    Py_Finalize();   

    return ;
}

namespace mpc {

const int ZK_PAILLIER_alpha = 6370;
const int ZK_PAILLIER_m2 = 11;

buf_t ZK_PAILLIER_P_non_interactive(const bn_t& N, const bn_t& phi_N, mem_t session_id)
{
  int N_len = N.get_bin_size();
  buf_t out(N_len*ZK_PAILLIER_m2);

  bn_t N_inv = bn_t::inverse_mod(N, phi_N);

  buf256_t seed = sha256_t::hash(N, session_id);

  crypto::ctr_aes_t ctr; 
  ctr.init(seed.lo, buf128_t(0));

  int enc_len = N_len/16+2;
  buf_t enc(enc_len); 

  int offset = 0;
  for (int i=0; i<ZK_PAILLIER_m2; i++, offset+=N_len)
  {
    enc.bzero();
    ctr.update(enc, enc.data());
    bn_t rho = bn_t::from_bin(enc);
    rho %= N;
    bn_t sigma = rho.pow_mod(N_inv, N);
    sigma.to_bin(out.data()+offset, N_len);
  }

  return out;
}

bool ZK_PAILLIER_V_non_interactive(const bn_t& N, mem_t pi, mem_t session_id)
{
  for (int i=0; ; i++)
  {
    int small_prime = small_primes[i];
    if (small_prime>ZK_PAILLIER_alpha) break;
    if ((N % small_prime)==0)
    {
      return false;
    }
  }

  int N_len = N.get_bin_size();
  if (pi.size != N_len*ZK_PAILLIER_m2)
  {
    return false;
  }

  buf256_t seed = sha256_t::hash(N, session_id);

  crypto::ctr_aes_t ctr; 
  ctr.init(seed.lo, buf128_t(0));

  int enc_len = N_len/16+2;
  buf_t enc(enc_len); 

  int offset = 0;
  for (int i=0; i<ZK_PAILLIER_m2; i++, offset+=N_len)
  {
    enc.bzero();
    ctr.update(enc, enc.data());
    bn_t rho = bn_t::from_bin(enc);
    rho %= N;
    bn_t sigma = bn_t::from_bin(mem_t(pi.data+offset, N_len));
    if (rho != sigma.pow_mod(N, N))
    {
      return false;
    }
  }

  return true;
}


//----------------------------------- zk_paillier_zero_t ---------------------------

void zk_paillier_zero_t::p(const bn_t& N, const bn_t& c, mem_t session_id, uint8_t aux, const bn_t& r)
{
  bn_t N2 = N*N;
  bn_t rho = bn_t::rand(N);
  bn_t a = rho.pow_mod(N, N2);
  
  e = bn_t(sha256_t::hash(N, c, a, session_id, aux));
  MODULO(N2) z = rho * r.pow(e);
}

bool zk_paillier_zero_t::v(const bn_t& N, const bn_t& c, mem_t session_id, uint8_t aux) const
{
  bn_t N2 = N*N;
  bn_t a;
  MODULO(N2) a = z.pow(N) / c.pow(e);

  if (bn_t::gcd(a, N) != 1) 
  {
    return false;
  }

  if (bn_t::gcd(c, N) != 1) 
  {
    return false;
  }

  if (bn_t::gcd(z, N) != 1) 
  {
    return false;
  }

  bn_t e_tag = bn_t(sha256_t::hash(N, c, a, session_id, aux));
  return e==e_tag;
}


//----------------------------------- zk_paillier_m_t --------------------------- 
// added by XF Song, proving plaintext equal to `m`

void zk_paillier_m_t::p(const bn_t& N, const bn_t& c, const bn_t& m, mem_t session_id, uint8_t aux, const bn_t& r)
{
  bn_t N2 = N * N;
  bn_t rho = bn_t::rand(N);
  bn_t a = rho.pow_mod(N, N2);

  _r = bn_t::rand(N);
  MODULO(N2) _c = (m * N + 1) * _r.pow(N);// _c = Enc(m, _r)

  e = bn_t(sha256_t::hash(N, c, _r, _c, a, session_id, aux));
  MODULO(N) z = rho * (r/_r).pow(e);
}

bool zk_paillier_m_t::v(const bn_t& N, const bn_t& c, const bn_t& m, mem_t session_id, uint8_t aux) const
{
  bn_t N2 = N*N;
  bn_t a;
  MODULO(N2) a = z.pow(N) / (c / _c).pow(e);

  if (bn_t::gcd(a, N) != 1) 
  {
    return false;
  }

  if (bn_t::gcd(c, N) != 1) 
  {
    return false;
  }

  if (bn_t::gcd(_c, N) != 1) // check _c
  {
    return false;
  }

  if (bn_t::gcd(z, N) != 1) 
  {
    return false;
  }

  bn_t e_tag = bn_t(sha256_t::hash(N, c, _r, _c, a, session_id, aux));
  return e==e_tag;
}

//----------------------------------- zk_paillier_mult_t ---------------------------
// added by XF Song, proving multiplication relation

void zk_paillier_mult_t::p(const bn_t& N, const bn_t& c_a, const bn_t& c_b, const bn_t& c_c, mem_t session_id, uint8_t aux, 
                                          const bn_t& a, const bn_t& b, const bn_t& c, const bn_t& r_a, const bn_t& r_b, const bn_t& r_c)
{
  bn_t N2 = N * N;
  bn_t d = bn_t::rand(N);
  bn_t r_d = bn_t::rand(N); 
  bn_t r_db = bn_t::rand(N);
  
  crypto::paillier_t paillier;
  paillier.create_pub(N);
  c_d = paillier.encrypt(d, r_d); //(d * N + 1) * r_d.pow(N); // Enc(d, r_d)
  c_db = paillier.encrypt(d*b, r_db); //(d * b * N + 1) * r_db.pow(N); // Enc(db, r_db)

  // printf("gcd(c_d, N): %s\n\n", bn_t::gcd(c_d, N).to_string().c_str());

  e = bn_t(sha256_t::hash(N, c_a, c_b, c_c, c_d, c_db, session_id, aux));

  MODULO(N2) c_1 = c_a.pow(e) * c_d;
  MODULO(N) f = e * a + d;
  MODULO(N2) c_2 = c_b.pow(f) * (c_db * c_c.pow(e)).inv();

  MODULO(N) z_1 = r_a.pow(e) * r_d; 
  MODULO(N) z_2 = r_b.pow(f) * (r_db * r_c.pow(e)).inv();
}

bool zk_paillier_mult_t::v(const bn_t& N, const bn_t& c_a, const bn_t& c_b, const bn_t& c_c, mem_t session_id, uint8_t aux) const
{
  bn_t N2 = N*N;
  if (bn_t::gcd(c_1, N) != 1) 
  {
    return false;
  }

  if (bn_t::gcd(c_2, N) != 1) 
  {
    return false;
  }

  if (bn_t::gcd(z_1, N) != 1)
  {
    return false;
  }

  if (bn_t::gcd(z_2, N) != 1) 
  {
    return false;
  }

  if (bn_t::gcd(f, N) != 1) 
  {
    return false;
  }

  if (bn_t::gcd(c_db, N) != 1) 
  {
    printf("gcd(c_db, N)\n\n");
    return false;
  }


  if (bn_t::gcd(c_d, N) != 1) 
  {
    printf("gcd(c_d, N)\n\n");
    return false;
  }


  bool valid = false; 
  MODULO(N2) valid = c_1 == (f * N + 1) * z_1.pow(N); // c_1 == Enc(f, z_1)
  if (!valid)
  {
    return false;
  }

  MODULO(N2) valid = c_2 == z_2.pow(N); // c_2 == Enc(0, z_2)
  if (!valid)
  {
    return false;
  }

  bn_t e_tag = bn_t(sha256_t::hash(N, c_a, c_b, c_c, c_d, c_db, session_id, aux));
  return e==e_tag;
}

//------------- zk_paillier_range_t ---------------------------------------

struct paillier_enc_info_t
{
  const bn_t* src;
  const bn_t* rand;
  bn_t* dst;
};

class paillier_enc_thread_t : public ub::thread_t
{
public:
  virtual void run() override
  {
    int n = (int)infos.size();
    for (int i=0; i<n; i++) *infos[i].dst = paillier->encrypt(*infos[i].src, *infos[i].rand);
  }

  void add(const bn_t* src, const bn_t* rand, bn_t* dst)
  {
    paillier_enc_info_t info; info.src = src; info.rand = rand; info.dst = dst;
    infos.push_back(info);
  }
  void set_paillier(const crypto::paillier_t& paillier)
  {
    this->paillier = &paillier;
  }

private:
  std::vector<paillier_enc_info_t> infos;
  const crypto::paillier_t* paillier;
};


void zk_paillier_range_t::p(bool threaded, const bn_t& q, const crypto::paillier_t& paillier, const bn_t& c_key, mem_t session_id, uint8_t aux, const bn_t& x_original, const bn_t& r)
{
  bn_t N = paillier.get_N();
  bn_t x = x_original;
  bn_t l = q / 3;
  bn_t l2 = l * 2;
  bn_t l3 = l * 3;

  bn_t w1[t];
  bn_t w2[t];
  bn_t c1[t];
  bn_t c2[t];
  bn_t r1[t];
  bn_t r2[t];
  buf128_t rnd = buf128_t::rand();

  for (int i=0; i<t; i++) 
  {
    w2[i] = bn_t::rand(l);
    w1[i] = l + w2[i];

    if (rnd.get_bit(i)) 
    {
      std::swap(w1[i], w2[i]);
    }

    r1[i] = bn_t::rand(N);
    r2[i] = bn_t::rand(N);
  }

  int cores = threaded ? ub::get_cpu_count() : 1;
  if (cores<1) cores = 1;
  std::vector<paillier_enc_thread_t> threads(cores);

  for (int i=0; i<t; i++) 
  {
    int thread_index = i % cores;
    threads[thread_index].add(w1+i, r1+i, c1+i);
    threads[thread_index].add(w2+i, r2+i, c2+i);
  }

  for (int i=0; i<cores; i++) threads[i].set_paillier(paillier);
  for (int i=0; i<cores-1; i++) threads[i].start();
  threads[cores-1].run();
  for (int i=0; i<cores-1; i++) threads[i].join();

  /*for (int i=0; i<t; i++) 
  {
    c1[i] = paillier.encrypt(w1[i], r1[i]);
    c2[i] = paillier.encrypt(w2[i], r2[i]);
  }*/


  sha256_t sha256;
  for (int i=0; i<t; i++) 
  {
    sha256.update(c1[i]);
    sha256.update(c2[i]);
  }

  u = 0;

       if (x < l)  u = 0;
  else if (x < l2) u = 1;
  else if (x < l3) u = 2;
  else if (x < q)  u = 3;
  else assert(false);

  bn_t c = paillier.sub_scalar(c_key, l * u);
  x = x - (l * u);
  
  sha256.update(u);
  sha256.update(c_key);
  sha256.update(N);
  sha256.update(session_id);
  sha256.update(aux);

  e = sha256.final().lo; // 16 bytes

  for (int i=0; i<t; i++) 
  {
    bool ei = e.get_bit(i);
    if (!ei)
    {
      infos[i].a = w1[i];
      infos[i].b = r1[i];
      infos[i].c = w2[i];
      infos[i].d = r2[i];
    }
    else
    {
      int j = 0;
           if (x + w1[i] >= l && x + w1[i] <= l2) j = 1;
      else if (x + w2[i] >= l && x + w2[i] <= l2) j = 2;
      else assert(false);

      infos[i].a = j;
      infos[i].b = x + ((j==1) ? w1[i] : w2[i]);
      MODULO(N) infos[i].c = r * ((j==1) ? r1[i] : r2[i]);
      infos[i].d = (j==2) ? c1[i] : c2[i];
    }
  }
}

bool zk_paillier_range_t::v(bool threaded, const bn_t& q, const bn_t& N, const bn_t& c_key, mem_t session_id, uint8_t aux) const
{
  bn_t N2 = N*N;

  bn_t l = q / 3;
  bn_t l2 = l * 2;

  crypto::paillier_t paillier; paillier.create_pub(N);
  bn_t c = paillier.sub_scalar(c_key, l * u);
  int j;

  int cores = threaded ? ub::get_cpu_count() : 1;
  if (cores<1) cores = 1;
  std::vector<paillier_enc_thread_t> threads(cores);

  bn_t c1_tab[t];
  bn_t c2_tab[t];
  //bn_t c_tag_tab[t];

  for (int i=0; i<t; i++) 
  {
    //bn_t c1, c2;
    int thread_index = i % cores;

    bool ei = e.get_bit(i);
    if (!ei)
    {
      bn_t w1 = infos[i].a;
      bn_t w2 = infos[i].c;
      if (w1<w2)
      {
        if (w1<0) return false;
        if (w1>l) return false;
        if (w2<l) return false;
        if (w2>l2) return false;
      }
      else
      {
        if (w2<0) return false;
        if (w2>l) return false;
        if (w1<l) return false;
        if (w1>l2) return false;
      }

      //bn_t r1 = infos[i].b;
      //bn_t r2 = infos[i].d;
      //c1 = paillier.encrypt(w1, r1);
      //c2 = paillier.encrypt(w2, r2);
      threads[thread_index].add(&infos[i].a, &infos[i].b, &c1_tab[i]); 
      threads[thread_index].add(&infos[i].c, &infos[i].d, &c2_tab[i]); 
    }
    else
    {
      if (infos[i].a!=1 && infos[i].a!=2) return false;
      j = (int)infos[i].a;

      bn_t wi = infos[i].b;
      if (wi<l) return false;
      if (wi>l2) return false;

      //bn_t ri = infos[i].c;
      //bn_t c_tag = paillier.encrypt(wi, ri);
      threads[thread_index].add(&infos[i].b, &infos[i].c, &c1_tab[i]); 
    }
  }

  for (int i=0; i<cores; i++) threads[i].set_paillier(paillier);
  for (int i=0; i<cores-1; i++) threads[i].start();
  threads[cores-1].run();
  for (int i=0; i<cores-1; i++) threads[i].join();

  sha256_t sha256;
  for (int i=0; i<t; i++) 
  {
    bn_t c1, c2;

    bool ei = e.get_bit(i);
    if (!ei)
    {
      c1 = c1_tab[i];
      c2 = c2_tab[i];
    }
    else
    {
      j = (int)infos[i].a;

      MODULO(N2) c1 = c1_tab[i] / c;
      c2 = infos[i].d;

      if (j==2) std::swap(c1, c2);
    }

    sha256.update(c1);
    sha256.update(c2);
  }

  sha256.update(u);
  sha256.update(c_key);
  sha256.update(N);
  sha256.update(session_id);
  sha256.update(aux);

  buf128_t e_tag = sha256.final().lo; // 16 bytes
  if (e != e_tag)
  {
    return false;
  }

  return true;
}

//-------------------------------------- zk_pdl_t ------------------------------
void zk_pdl_t::p(ecurve_t curve, const ecc_point_t& Q, const bn_t& c_key, const paillier_t& paillier, mem_t session_id, uint8_t aux, const bn_t& r_key, const bn_t& x1)
{
  const bn_t& q = curve.order();
  const ecc_generator_point_t& G = curve.generator();
 
  bn_t N = paillier.get_N();
  bn_t r = bn_t::rand(q);
  bn_t r_rand = bn_t::rand(N);					//(*)
  c_r = paillier.encrypt(r,r_rand);				//(*)
  R = G * r;
  bn_t rho = bn_t::rand(q.sqr());
  bn_t rho_rand = bn_t::rand(N);				//(*)
  c_rho =  paillier.encrypt(rho*q, rho_rand);			//(*)
 
  bn_t e = bn_t(sha256_t::hash(c_key, N, Q, c_r, R, c_rho, session_id, aux));
  bn_t temp = paillier.mul_scalar(c_key, e);
  bn_t temp2 = paillier.add_ciphers(c_r, temp);
  bn_t c_z = paillier.add_ciphers(temp2, c_rho);
  z = r + (e * x1) + (rho * q);
 
  bn_t c_tag = paillier.sub_scalar(c_z, z);
 
  bn_t r_temp = r_key.pow_mod(e, N);				//(*)
  bn_t r_tag;
  MODULO(N) r_tag = r_temp * r_rand * rho_rand;		//(*)
 
  zk_paillier_zero.p(N, c_tag, session_id, aux, r_tag);
 
  zk_paillier_range.p(true, q, paillier, c_key, session_id, aux, x1, r_key);
}


bool zk_pdl_t::v(ecurve_t curve, const ecc_point_t& Q, const bn_t& c_key, const bn_t& N, mem_t session_id, uint8_t aux) const
{
  const bn_t& q = curve.order();
  const ecc_generator_point_t& G = curve.generator();

  paillier_t paillier; paillier.create_pub(N);

  bn_t e = bn_t(sha256_t::hash(c_key, N, Q, c_r, R, c_rho, session_id, aux));

  bn_t temp = paillier.mul_scalar(c_key, e);
  bn_t temp2 = paillier.add_ciphers(c_r, temp);
  bn_t c_z = paillier.add_ciphers(temp2, c_rho);

  ecc_point_t P = G*z;
  if (P != R + Q*e) 
  {
    return false;
  }
  if (z<0 || z>=N) 
  {
    return false;
  }

  bn_t c_tag = paillier.sub_scalar(c_z, z);

  if (!zk_paillier_zero.v(N, c_tag, session_id, aux)) 
  {
    return false;
  }


  if (!zk_paillier_range.v(true, q, N, c_key, session_id, aux)) 
  {
    return false;
  }
  return true;
}

//-------------------------------------- zk_pdl_mult_t ------------------------------ 
// Added by XF Song

void zk_pdl_mult_t::p(ecurve_t curve, const ecc_point_t X, const bn_t c_1, const bn_t c_2, const crypto::paillier_t& paillier, const bn_t h_1, const bn_t h_2, const bn_t _N, mem_t session_id, uint8_t aux, 
         const bn_t x, const bn_t y, const bn_t r)
{
  const bn_t& q = curve.order();
  const ecc_generator_point_t& G = curve.generator();

  bn_t N = paillier.get_N();
  
  bn_t alpha = bn_t::rand(q.pow(3));
  bn_t rho = bn_t::rand(q * _N);
  bn_t _rho = bn_t::rand(q.pow(3) * _N);
  bn_t sigma = bn_t::rand(q * _N);
  bn_t beta = bn_t::rand(N);
  bn_t gamma = bn_t::rand(N);
  bn_t tau = bn_t::rand(q * _N);

  U = G * alpha;
  MODULO(_N) z = h_1.pow(x) * h_2.pow(rho);
  MODULO(_N) _z = h_1.pow(alpha) * h_2.pow(_rho);
  MODULO(_N) t = h_1.pow(y) * h_2.pow(sigma);

  bn_t tmp = paillier.encrypt(gamma, beta);
  bn_t tmp2 = paillier.mul_scalar(c_1, alpha);
  k = paillier.add_ciphers(tmp, tmp2);

  MODULO(_N) w = h_1.pow(gamma) * h_2.pow(tau);
  
  bn_t e = bn_t(sha256_t::hash(X, c_1, c_2, h_1, h_2, U, z, _z, t, k, w, session_id, aux)) % q;

  MODULO(N) s = r.pow(e) * beta;
  s_1 = e * x + alpha;
  s_2 = e * rho + _rho;
  t_1 = e * y + gamma;
  t_2 = e * sigma + tau;

//printf("in zk_pdl_mult_t::v: \n\n %s, \n\n %s \n\n", N.to_string().c_str(), f2.to_string().c_str());

}


bool zk_pdl_mult_t::v(ecurve_t curve, const ecc_point_t X, const bn_t N, const bn_t c_1, const bn_t c_2, const bn_t h_1, const bn_t h_2, const bn_t _N, mem_t session_id, uint8_t aux) const
{
// printf("in zk_pdl_mult_t::v 0 \n");
  bn_t N2 = N * N;

  const bn_t& q = curve.order();
// printf("in zk_pdl_mult_t::v: \n\n %s\n\n", N.to_string().c_str());

  const ecc_generator_point_t& G = curve.generator();

  paillier_t paillier; paillier.create_pub(N);
  bn_t e = bn_t(sha256_t::hash(X, c_1, c_2, h_1, h_2, U, z, _z, t, k, w, session_id, aux)) % q;

// printf("in zk_pdl_mult_t::v 0 \n");
  if (! (s_1 <= q.pow(3))) 
  {
    return false;
  }

// printf("in zk_pdl_mult_t::v 1 \n");
  ecc_point_t P = X * e + U;
  if (P != G * s_1) 
  {
    return false;
  }

// printf("in zk_pdl_mult_t::v 2 \n");
  bn_t tmp, tmp2;
  MODULO(_N) tmp = h_1.pow(s_1) * h_2.pow(s_2);
  MODULO(_N) tmp2 = z.pow(e) * _z;
  if (tmp != tmp2)
  {
    return false;
  }

// printf("in zk_pdl_mult_t::v 3 \n");
  MODULO(_N) tmp = h_1.pow(t_1) * h_2.pow(t_2);
  MODULO(_N) tmp2 = t.pow(e) * w;
  if (tmp != tmp2)
  {
    return false;
  }

// printf("in zk_pdl_mult_t::v 4 \n");
  tmp = paillier.mul_scalar(c_1, s_1);
  tmp2 = paillier.encrypt(t_1, s);
  bn_t c_tmp = paillier.add_ciphers(tmp, tmp2); 

  bn_t c_tmp2;
  MODULO(N2) c_tmp2 = c_2.pow(e) * k;

// printf("in zk_pdl_mult_t::v: \n\n %s, \n\n %s \n\n", N.to_string().c_str(), c_tmp2.to_string().c_str());
// printf("in zk_pdl_mult_t::v 5 \n");  
  if (c_tmp != c_tmp2)
  {
    return false;
  }
// printf("in zk_pdl_mult_t::v 6 \n");  
// printf("done. \n\n");
  return true;
}


// -------------------------------------------------------

void zk_DF_nonneg_t::p(const bn_t com, const bn_t G, const bn_t H, const bn_t _N, const int bits, mem_t session_id, uint8_t aux, 
         const bn_t u, const bn_t rho)
{
  // assert(u == (u_1 + u_2 + u_3 + u_4));

  bn_t F = bn_t(2).pow(80), T = bn_t(2).pow(bits), t = 160, B = bits;
  bn_t R1, R2, R3, R4;
  R1 = bn_t(2).pow(B + t);

// logger::log(logger::INFO) << "in zk_DF_nonneg_t, R1 done." <<std::endl;


  R2 = bn_t(2).pow(t) * F * bn_t(2).pow(bits/2);

// logger::log(logger::INFO) << "in zk_DF_nonneg_t, R2 done." <<std::endl;

  R3 = bn_t(2).pow(B + t * 2) * F;

// logger::log(logger::INFO) << "in zk_DF_nonneg_t, R3 done." <<std::endl;

  R4 = bn_t(2).pow(B + t * 2) * F *  bn_t(2).pow(bits/2);

// logger::log(logger::INFO) << "in zk_DF_nonneg_t, R4 done." <<std::endl;


  bn_t rph_array[4], m1_array[4], r2_array[4], u_array[4];

// std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
   
  RS(u, u_array); // u = u_1^2 + u_2^2 + u_3^2 + u_4^2

// std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
    
// double d1 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
// logger::log(logger::INFO) << "time for RS:"  << d1 << " us" <<std::endl;


  bn_t tmp = rho;
  for (int i = 0; i < 3; i++) {
    rph_array[i] = bn_t::rand(R1);
    tmp = tmp - rph_array[i];
  }
  rph_array[3] = tmp;
// assert(rho == rph_array[0] + rph_array[1] + rph_array[2] + rph_array[3]);

// bn_t test = 4, test_tmp, n = bn_t(17);
// MODULO(n) test_tmp = bn_t(2).pow(test);

// logger::log(logger::INFO) << "in zk_DF_nonneg_t, for done." <<std::endl;

  bn_t r_3 = bn_t::rand(R4);
  MODULO(_N)  c_3 = H.pow(r_3);
  for (int i = 0; i < 4; i++) {
    m1_array[i] = bn_t::rand(R2);
    r2_array[i] = bn_t::rand(R3);
    MODULO(_N)  c_1[i] = G.pow(u_array[i]) * H.pow(rph_array[i]);
    MODULO(_N)  c_2[i] = G.pow(m1_array[i]) * H.pow(r2_array[i]);

    MODULO(_N)  c_3 = c_3 * c_1[i].pow(m1_array[i]);
  }

// logger::log(logger::INFO) << "in zk_DF_nonneg_t, before hash." <<std::endl;


  bn_t e = bn_t(sha256_t::hash(com, G, H, ub::convert(c_1), ub::convert(c_2), c_3, session_id, aux)) % F;

 // logger::log(logger::INFO) << e.to_string() <<std::endl;


  r_5 = 0;
  for (int i = 0; i < 4; i++) {
    m2_array[i] = m1_array[i] + e * u_array[i];
    r4_array[i] = r2_array[i] + e * rph_array[i];
    r_5 += (bn_t(1) - u_array[i]) * rph_array[i];
  }
  r_5 = r_3 + e * r_5;

// logger::log(logger::INFO) <<"in p " << r_5.to_string() <<std::endl;


//logger::log(logger::INFO) << m2_array[2].to_string() <<std::endl;

  //assert( m2_array[1] );
}
bool zk_DF_nonneg_t::v(const bn_t com, const bn_t G, const bn_t H, const bn_t _N, mem_t session_id, uint8_t aux) const
{

  bn_t F = bn_t(2).pow(80);

  bn_t e = bn_t(sha256_t::hash(com, G, H, ub::convert(c_1), ub::convert(c_2), c_3, session_id, aux)) % F;

 // logger::log(logger::INFO) << e.to_string() <<std::endl;

//logger::log(logger::INFO) <<"in v " << m2_array[2].to_string() <<std::endl;

// logger::log(logger::INFO) <<"in v " << r_5.to_string() <<std::endl;

  bn_t tmp = 1;
 
  for (int i = 0; i < 4; i++) {
    bn_t tmp1, tmp2;

    MODULO(_N) tmp1 = G.pow(m2_array[i]) * H.pow(r4_array[i]);
    MODULO(_N) tmp2 = c_1[i].pow(e) * c_2[i];

    if ( tmp1 != tmp2 ) {
      // logger::log(logger::ERROR) << "FAIL 1" <<std::endl;
      return false;
    }

    MODULO(_N) tmp *= c_1[i].pow(m2_array[i]);
  }
  bn_t tmp3 = 0;

  MODULO(_N) tmp = tmp * H.pow(r_5);
  MODULO(_N) tmp3 = com.pow(e) * c_3;
  
  if (tmp != tmp3) {
    // logger::log(logger::ERROR) << "FAIL 2" <<std::endl;
    return false;
  }

  return true;
}

void zk_DF_Paillier_equal_t::p(const bn_t com, const bn_t ciphertext, const bn_t G, const bn_t H, const bn_t _N, const crypto::paillier_t paillier, const int bits, mem_t session_id, uint8_t aux, 
         const bn_t u, const bn_t rho_enc, const bn_t rho_com)
{
  bn_t F = bn_t(2).pow(80), T = bn_t(2).pow(bits), t = 160, B = bits;
  bn_t R1, R2;
  R1 = bn_t(2).pow(t) * F * T;
  R2 = bn_t(2).pow(B + t * 2) * F;
  
  bn_t N = paillier.get_N();

  bn_t m_1 = bn_t::rand(R1);
  bn_t r_1 = bn_t::rand(N);
  bn_t r_2 = bn_t::rand(R2);

  c_3 = paillier.encrypt(m_1, r_1);
  MODULO(_N) c_4 = G.pow(m_1) * H.pow(r_2);

  bn_t e = bn_t(sha256_t::hash(com, ciphertext, G, H, session_id, aux)) % F;

/* bn_t fuck;
MODULO(_N) fuck = G.pow(u) * H.pow(rho_com);
assert( fuck == com );
assert( paillier.encrypt(u, rho_enc) == ciphertext ); 
*/

  m_2 = m_1 + e * u;
  MODULO(N) r_3 = r_1 * rho_enc.pow(e);
  r_4 = r_2 + e * rho_com;

// logger::log(logger::INFO) <<"DATA " << ((m_1 + u * e ) % N).to_string()  <<std::endl;

}

bool zk_DF_Paillier_equal_t::v(const bn_t com, const bn_t ciphertext,  const bn_t G, const bn_t H, const bn_t _N, const bn_t N,  const int bits, mem_t session_id, uint8_t aux) const
{
  bn_t F = bn_t(2).pow(80);
  bn_t e = bn_t( sha256_t::hash(com, ciphertext, G, H, session_id, aux) ) % F;

  crypto::paillier_t paillier;
  paillier.create_pub(N);

  bn_t tmp = paillier.add_ciphers(c_3, paillier.mul_scalar(ciphertext, e));
  if ((tmp - paillier.encrypt(m_2, r_3)) % N != 0 ) {
    // logger::log(logger::ERROR) << "FAIL 1 : "<<std::endl;
    return false;
  }

  MODULO(_N) tmp = c_4 * com.pow(e) - G.pow(m_2) * H.pow(r_4);
  if(tmp != 0){
    // logger::log(logger::ERROR) << "FAIL 2" <<std::endl;
    return false;
  }

  return true;
}

void zk_DF_com_range_t::p(const bn_t com, const bn_t a, const bn_t b, const bn_t G, const bn_t H, const bn_t _N, const int bits, mem_t session_id, uint8_t aux, const bn_t u, const bn_t rho) 
{
  // generate axulary commitment
  r_a = bn_t::rand(_N);
  r_b = bn_t::rand(_N);
  MODULO(_N) com_a = G.pow(a) * H.pow(r_a);
  MODULO(_N) com_b = G.pow(b) * H.pow(r_b);

  // compute com(u-a, rho-r_a) and com(b-u, r_b-rho)
  bn_t com_na, com_nb;
  MODULO(_N) com_na = com / com_a;
  MODULO(_N) com_nb = com_b / com;

 //logger::log(logger::ERROR) << com_na.to_string() <<std::endl;

  // FIXME: fix this bug
  /*bn_t test, test2;
  MODULO(_N) test = G.pow(u) * H.pow(rho) /(G.pow(a) * H.pow(r_a));
  MODULO(_N) test2 = G.pow(u - a) * H.pow(rho - r_a);
  assert( test == test2 );

  MODULO(_N) test = G.pow(b - u) * H.pow(r_b - rho);
  assert( test == com_nb);
  */

  nonneg_a.p(com_na, G, H, _N, bits, session_id, aux, u - a, rho - r_a) ;
  nonneg_b.p(com_nb, G, H, _N, bits, session_id, aux, b - u, r_b - rho) ;

}

bool zk_DF_com_range_t::v(const bn_t com, const bn_t a, const bn_t b, const bn_t G, const bn_t H, const bn_t _N, const int bits, mem_t session_id, uint8_t aux) const 
{
  bn_t test_zero_1, test_zero_2;

  MODULO(_N) test_zero_1 = com_a - G.pow(a) * H.pow(r_a);
  if (test_zero_1 != 0) {
    return false;
  } 

  MODULO(_N) test_zero_2 = com_b - G.pow(b) * H.pow(r_b);
  if (test_zero_2 != 0) {
    return false;
  }

  bn_t com_na, com_nb;
  MODULO(_N) com_na = com / com_a;
  MODULO(_N) com_nb = com_b / com;


  if(!nonneg_a.v(com_na, G, H, _N, session_id, aux)) {
    return false;
  }

  if(!nonneg_b.v(com_nb, G, H, _N, session_id, aux)) {
    return false;
  }

  return true;
}

void zk_DF_Paillier_range_t::p(const bn_t ciphertext, const bn_t a, const bn_t b, const bn_t G, const bn_t H, const bn_t _N, const crypto::paillier_t paillier, const int bits, mem_t session_id, uint8_t aux, const bn_t u, const bn_t rho_enc)
{
  bn_t rho_com = bn_t::rand(_N);
  MODULO(_N) com = G.pow(u) * H.pow(rho_com);

  equal_proof.p(com, ciphertext, G, H, _N, paillier, bits, session_id, aux, u, rho_enc, rho_com);
  range_proof.p(com, a, b, G, H, _N, bits, session_id, aux, u, rho_com);
}

bool zk_DF_Paillier_range_t::v(const bn_t ciphertext, const bn_t a, const bn_t b, const bn_t G, const bn_t H, const bn_t _N, const bn_t N,  const int bits, mem_t session_id, uint8_t aux) const
{

  if (! equal_proof.v(com, ciphertext, G, H, _N, N, bits, session_id, aux)) {
    logger::log(logger::ERROR) << "zk_DF_Paillier_range_t equal_proof.v() failed." <<std::endl;
    return false;
  }

  if (! range_proof.v(com, a, b, G, H, _N, bits, session_id, aux)){
    logger::log(logger::ERROR) << "zk_DF_Paillier_range_t range_proof.v() failed." <<std::endl;
    return false;
  }

  return true;
}
// ------------------------------ zk_dl ------------------------

static bn_t zk_dl_hash(const ecc_point_t& G, const ecc_point_t& Q, const ecc_point_t& X, mem_t session_id, uint8_t aux)
{
  return bn_t(sha256_t::hash(G, Q, X, session_id, aux));
}


void zk_dl_t::p(ecurve_t curve, const ecc_point_t& Q, mem_t session_id, uint8_t aux, const bn_t& d)
{
  const bn_t& order = curve.order();
	bn_t sigma = bn_t::rand(order);
  const ecc_generator_point_t& G = curve.generator();
  ecc_point_t X = G * sigma;

  e = zk_dl_hash(G, Q, X, session_id, aux);
	
  MODULO(order)
  {
    u = e * d + sigma;
  }
}

bool zk_dl_t::v(ecurve_t curve, const ecc_point_t& Q, mem_t session_id, uint8_t aux) const
{
  assert(curve.check(Q));

  const ecc_generator_point_t& G = curve.generator();
  ecc_point_t X = G * u - Q * e;

  bn_t etag = zk_dl_hash(G, Q, X, session_id, aux);
  if (etag != e)
  {
    return false;
  }
  return true;
}


// ------------------------------ zk_ddh ------------------------

static buf_t hash_zk_ddh(
  const ecc_point_t& G, 
  const ecc_point_t& Q, 
  const ecc_point_t& A, 
  const ecc_point_t& B, 
  const ecc_point_t& X, 
  const ecc_point_t& Y, 
  mem_t session_id,
  uint8_t aux)
{
  return sha256_t::hash(G, Q, A, B, X, Y, session_id, aux);
}

void zk_ddh_t::p(
  ecurve_t curve, 
  const ecc_point_t& Q, 
  const ecc_point_t& A, 
  const ecc_point_t& B, 
  const bn_t& w, 
  mem_t session_id,
  uint8_t aux)  // output
{
  const ecc_generator_point_t& G = curve.generator();
  bn_t sigma = curve.get_random_value();
  
  ecc_point_t X = G * sigma;
  ecc_point_t Y = Q * sigma;

  e_buf = hash_zk_ddh(G, Q, A, B, X, Y, session_id, aux);
  bn_t e = bn_t::from_bin(e_buf);
  const bn_t& order = curve.order();
  
  MODULO(order)  { u = sigma + e * w; }
}

bool zk_ddh_t::v(
  ecurve_t curve, 
  const ecc_point_t& Q, 
  const ecc_point_t& A,
  const ecc_point_t& B, 
  mem_t session_id,
  uint8_t aux) const
{
  const ecc_generator_point_t& G = curve.generator();
  bn_t e = bn_t::from_bin(e_buf);

  ecc_point_t X = G * u - A * e;
  ecc_point_t Y = Q * u - B * e;

  buf_t h = hash_zk_ddh(G, Q, A, B, X, Y, session_id, aux);
  return secure_equ(h, e_buf);
}


// ----------------- zk_ec_affine_t ----------------
void zk_ec_affine_t::p(const ecc_point_t& P, const ecc_point_t& U, const ecc_point_t& V, const ecc_point_t& U_tag, const ecc_point_t& V_tag, mem_t session_id, const bn_t& s, const bn_t& w, const bn_t& r_tag)
{
  ecurve_t curve = crypto::curve_p256;
  assert(P.get_curve()==curve);
  assert(U.get_curve()==curve);
  assert(V.get_curve()==curve);
  assert(U_tag.get_curve()==curve);
  assert(V_tag.get_curve()==curve);

  const bn_t& q = curve.order();
  const ecc_generator_point_t& G = curve.generator();

  bn_t alpha = curve.get_random_value();
  bn_t beta  = curve.get_random_value();
  bn_t gamma = curve.get_random_value();

  ecc_point_t A = G * alpha + U * beta;
  ecc_point_t B = P * alpha + V * beta + G * gamma;

  buf256_t hash = sha256_t::hash(P, U, V, U_tag, V_tag, A, B, session_id);
  e = bn_t(hash.lo);

  MODULO(q)
  {
    z1 = alpha + e * r_tag;
    z2 = beta + e * s;
    z3 = gamma + e * w;
  }
}

bool zk_ec_affine_t::v(const ecc_point_t& P, const ecc_point_t& U, const ecc_point_t& V, const ecc_point_t& U_tag, const ecc_point_t& V_tag, mem_t session_id) const
{
  ecurve_t curve = crypto::curve_p256;
  assert(P.get_curve()==curve);
  assert(U.get_curve()==curve);
  assert(V.get_curve()==curve);
  assert(U_tag.get_curve()==curve);
  assert(V_tag.get_curve()==curve);

  const bn_t& q = curve.order();
  const ecc_generator_point_t& G = curve.generator();

  ecc_point_t A = G * z1 + U * z2 - U_tag * e;
  ecc_point_t B = P * z1 + V * z2 + G * z3 - V_tag * e;

  buf256_t hash = sha256_t::hash(P, U, V, U_tag, V_tag, A, B, session_id);
  bn_t e_tag = bn_t(hash.lo);

  if (e_tag != e)
  {
    return false;
  }

  return true;
}


// --------------------------------------------------- equality_test_t -----------------

struct equality_test_private_key_t
{
  equality_test_private_key_t();
  ecc_point_t P;
  bn_t x;
  zk_dl_t zk_dl;
};
ub::global_t<equality_test_private_key_t> g_equality_test_private_key;

equality_test_private_key_t::equality_test_private_key_t()
{
  ecurve_t curve = crypto::curve_p256;
  const ecc_generator_point_t& G = curve.generator();
  x = curve.get_random_value();
  P = G * x;
  zk_dl.p(curve, P, mem_t(), 0, x);
}

struct equality_test_public_key_t
{
  ub::mutex_t lock;
  ecc_point_t P;
};
ub::global_t<equality_test_public_key_t> g_equality_test_public_key;


void equality_test_t::peer1_step1(message1_t& out)
{
  const equality_test_private_key_t& prv_key = g_equality_test_private_key.instance();

  ecurve_t curve = crypto::curve_p256;
  const bn_t& q = curve.order();
  const ecc_generator_point_t& G = curve.generator();
  bn_t a = bn_t(value_hash) % q;

  bn_t r = curve.get_random_value();
  out.zk_dl = prv_key.zk_dl;
  out.P = prv_key.P;
  out.U = U = G * r;
  out.V = V = out.P * r - G * a;
}

error_t equality_test_t::peer2_step1(const message1_t& in, message2_t& out)
{
  error_t rv = 0;
  ecurve_t curve = crypto::curve_p256;
  const bn_t& q = curve.order();

  const ecc_generator_point_t& G = curve.generator();
  if (!curve.check(in.U)) return ub::error(E_BADARG);
  if (!curve.check(in.V)) return ub::error(E_BADARG);

  equality_test_public_key_t& pub_key = g_equality_test_public_key.instance();
  ecc_point_t P;
  {
    ub::scoped_lock_t scoped(pub_key.lock);
    if (pub_key.P.valid()) P = pub_key.P;
  }

  if (!P.valid() || P != in.P)
  {
    if (!curve.check(in.P)) return rv = ub::error(E_BADARG);
    if (!in.zk_dl.v(curve, in.P, mem_t(), 0)) return rv = ub::error(E_BADARG);

    ub::scoped_lock_t scoped(pub_key.lock);
    pub_key.P = P = in.P;
  }

  bn_t s = curve.get_random_value();
  t = curve.get_random_value();
  bn_t r_tag = curve.get_random_value();
  bn_t b = bn_t(value_hash) % q;

  out.V_tag = ((in.V + G * b) * s) + (P * r_tag) + (G * t);
  out.U_tag = in.U * s + G * r_tag;

  bn_t w;
  MODULO (q) w = t + s * b;

  out.zk_ec_affine.p(P, in.U, in.V, out.U_tag, out.V_tag, mem_t(), s, w, r_tag);

  ecc_point_t P_tag = G * t;

  out.hash = sha256_t::hash(P_tag, value_hash);
  return rv;
}

error_t equality_test_t::peer1_step2(const message2_t& in, message3_t& out, bool& result)
{
  error_t rv = 0;

  ecurve_t curve = crypto::curve_p256;
  const bn_t& q = curve.order();

  if (!curve.check(in.U_tag)) return rv = ub::error(E_BADARG);
  if (!curve.check(in.V_tag)) return rv = ub::error(E_BADARG);

  const equality_test_private_key_t& prv_key = g_equality_test_private_key.instance();
  ecc_point_t P = prv_key.P;

  if (!in.zk_ec_affine.v(P, U, V, in.U_tag, in.V_tag, mem_t())) return rv = ub::error(E_BADARG);

  ecc_point_t P_tag = in.V_tag - in.U_tag * prv_key.x;

  buf256_t hash_tag = sha256_t::hash(P_tag, value_hash);
  result = (hash_tag == in.hash);
  if (result) out.P_tag = P_tag;

  return 0;
}

error_t equality_test_t::peer2_step2(const message3_t& in, bool& result)
{
  error_t rv = 0;
  result = false;

  if (!in.P_tag.valid())
  {
    return 0;
  }

  ecurve_t curve = crypto::curve_p256;
  const ecc_generator_point_t& G = curve.generator();
  if (!curve.check(in.P_tag)) return rv = ub::error(E_BADARG);

  if (in.P_tag != G * t) return rv = ub::error(E_CRYPTO);

  result = true;
  return 0;
}

} //namespace mpc