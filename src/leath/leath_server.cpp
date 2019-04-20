#include "leath_server.h"

using namespace ub;

namespace mpc
{

LeathServer::LeathServer(std::string path, uint8_t id) : server_path(path), server_id(id){}

error_t LeathServer::leath_setup_peer2_step1(mem_t session_id, int server_id, const leath_setup_message1_t &in, leath_setup_message2_t &out)
{
    error_t rv = 0;

    int paillier_size = 1024; //get_safe_paillier_bits(curve);

    if (in.N.get_bits_count() < paillier_size)
        return rv = error(E_CRYPTO);

    // printf("in peer2_step1, before ZK_PAILLIER_V_non_interactive.v:  %s \n\n", in.N.to_string().c_str());

    if (!mpc::ZK_PAILLIER_V_non_interactive(in.N, in.pi_RN, session_id))
        return rv = error(E_CRYPTO);
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
    // TODO:
    ecc_point_t pk, G;
    bn_t sk, order;
    ecurve_t curve = ecurve_t::find(NID_secp256k1);
    if (!curve)
        return ub::error(E_BADARG);

    G = curve.generator();
    order = curve.order();
    sk = bn_t::rand(order);
    pk = G * sk;

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
    server_share.pk = pk;
    server_share.sk = sk;

    out._c_i = paillier.add_ciphers(paillier.mul_scalar(in.c_1, sk), paillier.encrypt(r, r_r));

    out.pk_i = pk;
    out.zk_pdl_mult.p(curve, pk, in.c_1, out._c_i, paillier, server_share.h_1, server_share.h_2, server_share._N, session_id, 1, sk, r, r_r);

    int bits = curve.bits();
    if (server_id < 0)
        return rv = error(E_BADARG);
    MODULO(in.N) server_share.keys_share = in.N - r * bn_t(2).pow(bits * server_id);

    return 0;
}

error_t LeathServer::leath_setup_peer2_step2(mem_t session_id, int server_id, const leath_setup_message3_t &in)
{
    server_share.mac_key_share = in.mac_key_share;
    return 0;
}

error_t LeathServer::leath_share_peer2_step1(mem_t session_id, const leath_maced_share_t &in, leath_maced_share_t &out)
{
    // firstly add in with local keys_share
    out = add_constant(in, server_share.keys_share);

    // TODO: store somewhere
    return 0;
}

error_t LeathServer::leath_share_peer2_step1(mem_t session_id, const leath_maced_share_with_VID_t &in, leath_maced_share_with_VID_t &out)
{
    // firstly add in with local keys_share
    out.val_id = in.val_id;
    out.maced_share = add_constant(in.maced_share, server_share.keys_share);

    share_map[out.val_id] = out.maced_share;
    return 0;
}

error_t LeathServer::leath_reconstruct_peer2_step1(mem_t session_id, const uint64_t vid, leath_maced_share_t &out)
{
    error_t rv = 0;
    leath_maced_share_t tmp;

    rv = get_maced_share(vid, tmp);
    if (rv != 0) {
        logger::log(logger::ERROR) << "leath_reconstruct_peer2_step1(): Get Share Failed!" <<std::endl;
        return rv;
    }

    bn_t N2 = server_share.N * server_share.N;
    out.share = server_share.c_2.pow_mod(tmp.share, N2);
    out.mac_share = tmp.mac_share;

    return 0;
}

leath_maced_share_t LeathServer::add_shares(const leath_maced_share_t s_1, const leath_maced_share_t s_2)
{
    leath_maced_share_t ret;

    ret.share = s_1.share + s_2.share;
    ret.mac_share = s_1.mac_share + s_2.mac_share;

    return ret;
}

leath_maced_share_t LeathServer::add_constant(const leath_maced_share_t s, const bn_t e)
{
    leath_maced_share_t ret;

    if (server_share.server_id == 0)
    {
        MODULO(server_share.N) ret.share = s.share + e;
    }
    else
    {
        ret.share = s.share;
    }

    MODULO(server_share.N) ret.mac_share = s.mac_share + server_share.mac_key_share * e;

    return ret;
}

leath_maced_share_t LeathServer::multiply_constant(const leath_maced_share_t s_1, const bn_t e)
{
    leath_maced_share_t ret;
    MODULO(server_share.N)  ret.share = ret.share * e;
    MODULO(server_share.N)  ret.mac_share = ret.mac_share * e;

    return ret;
}

int32_t LeathServer::get_id()
{
    return server_id;
}

error_t LeathServer::get_maced_share(const uint64_t vid, leath_maced_share_t &s) {
    //TODO: how to get the maced share by vid!

    std::map<uint64_t, leath_maced_share_t>::iterator it;
    it = share_map.find(vid);
    if (it == share_map.end()){
        logger::log(logger::ERROR) << "get_maced_share(): Not find the matching share" << std::endl;
        return error(E_NOT_FOUND);
    }
    s = it->second;
    return 0;
}

} // namespace mpc