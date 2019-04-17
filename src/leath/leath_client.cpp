#include "leath_client.h"

using namespace ub;

namespace mpc
{
leath_client_share_t LeathClient::client_share;
std::mutex LeathClient::client_share_mutx_;

LeathClient::LeathClient(std::string path, int bits) : client_path(path), paillier_keysize(bits) {}

error_t LeathClient::leath_setup_peer1_step1(mem_t session_id, leath_setup_message1_t &out)
{

    crypto::paillier_t paillier, _paillier;
    paillier.generate(paillier_keysize, true);
    _paillier.generate(paillier_keysize, true);


    client_share.paillier = paillier;
    out.N =  paillier.get_N();

// printf("in leath_setup_peer1_step1: \n\n %s\n\n", out.N.to_string().c_str());



    // auxulary value
    out._N = client_share._N =_paillier.get_N();
    out.h_1 = client_share.h_1 = bn_t::rand(out._N);
    out.h_2 = client_share.h_2 = bn_t::rand(out._N);

    assert(out.N == paillier.get_N());

    out.pi_RN = ZK_PAILLIER_P_non_interactive(out.N, paillier.get_phi_N(), session_id);

    bn_t lambda, mu;
    bn_t r = eGCD(out.N, paillier.get_p(), paillier.get_q(), mu, lambda);
    assert(r == bn_t(1));

    bn_t r_1, r_2, r_3;
    r_1 = bn_t::rand(out.N);
    r_2 = bn_t::rand(out.N);
    r_3 = bn_t::rand(out.N);

    bn_t m1, m2;
    MODULO(out.N)  m1 = mu * paillier.get_p();
    MODULO(out.N)  m2 = lambda * paillier.get_q();

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

error_t LeathClient::leath_setup_peer1_step2(mem_t session_id, int server_id, const leath_setup_message2_t &in)
{
    error_t rv = 0;

    if (!in.zk_pdl_mult.v(in.pk_i.get_curve(), in.pk_i, client_share.paillier.get_N(), client_share.c_1, in._c_i, client_share.h_1, client_share.h_2, client_share._N, session_id, 1))
        return rv = error(E_CRYPTO);
// printf("in peer1_step2, after zk_pdl_mult.v \n");

    bn_t x_i = client_share.paillier.decrypt(in._c_i);

    if (server_id < 0)
        return rv = error(E_BADARG);
// printf("in peer1_step2, after server_id \n");
    ecurve_t curve = in.pk_i.get_curve();
    if (!curve)
        return rv = ub::error(E_BADARG);
    int bits = curve.bits();
// printf("in peer1_step2, after curve \n");
    // TODO: mayber return the share is better
    client_share_mutx_.lock();
    client_share.keys_share += x_i * bn_t(2).pow_mod(bn_t(bits * server_id), client_share.paillier.get_N());
    client_share_mutx_.unlock();
// printf("in peer1_step2, after mutx \n");

    return 0;
}
} // namespace mpc