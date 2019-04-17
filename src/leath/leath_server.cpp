#include "leath_server.h"

using namespace ub;

namespace mpc
{

    LeathServer::LeathServer(std::string path, int32_t id) : server_path(path), server_id(id) {}

    error_t LeathServer::leath_setup_peer2_step1(mem_t session_id, int server_id, ecc_point_t pk, bn_t sk, const leath_setup_message1_t &in, leath_setup_message2_t &out)
    {
        error_t rv = 0;

        int paillier_size = 1024; //get_safe_paillier_bits(curve);

        if (in.N.get_bits_count() < paillier_size)
            return rv = error(E_CRYPTO);

        // printf("in peer2_step1, before ZK_PAILLIER_V_non_interactive.v:  %s \n\n", in.N.to_string().c_str());

        if (!mpc::ZK_PAILLIER_V_non_interactive(in.N, in.pi_RN, session_id)) return rv = error(E_CRYPTO);
        // printf("in peer2_step1, after ZK_PAILLIER_V_non_interactive.v \n");

        crypto::paillier_t paillier;
        paillier.create_pub(in.N);

        if (!in.zk_paillier_zero.v(in.N, in.c_3, session_id, 1))
            return rv = error(E_CRYPTO);
        // printf("in peer2_step1, after zk_paillier_zero.v \n");

        if (!in.zk_paillier_m.v(in.N, paillier.add_ciphers(in.c_1, in.c_2), bn_t(1), session_id, 1))
            return rv = error(E_CRYPTO);
        // printf("in peer2_step1, after zk_paillier_m.v \n");

        if (!in.zk_paillier_mult.v(in.N, in.c_1, in.c_2, in.c_3, session_id, 1))
            return rv = error(E_CRYPTO);
        // printf("in peer2_step1, after zk_paillier_mult.v \n");

        // if all good, prepare return message
        ecurve_t curve = pk.get_curve();
        const bn_t &order = curve.order();

        bn_t r, r_r;
        r = bn_t::rand(in.N);
        r_r = bn_t::rand(in.N);

        // TODO: store locally
        server_share.N = in.N;
        server_share.c_1 = in.c_1;
        server_share.c_2 = in.c_2;
        server_share.h_1 = in.h_1;
        server_share.h_2 = in.h_2;
        server_share._N = in._N;

        out._c_i = paillier.add_ciphers(paillier.mul_scalar(in.c_1, sk), paillier.encrypt(r, r_r));

        out.pk_i = pk;
        out.zk_pdl_mult.p(curve, pk, in.c_1, out._c_i, paillier, server_share.h_1, server_share.h_2, server_share._N, session_id, 1, sk, r, r_r);


        int bits = curve.bits();
        if (server_id < 0)
            return rv = error(E_BADARG);
        MODULO(in.N) server_share.keys_share = in.N - r * bn_t(2).pow(bits * server_id);

        return 0;
    }
} // namespace mpc