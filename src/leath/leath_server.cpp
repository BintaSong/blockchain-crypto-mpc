#include "leath_server.h"

using namespace ub;

namespace mpc
{
    

LeathServer::LeathServer(const std::string path, const uint8_t id) : server_dir(path), server_id(id){
    
}

LeathServer::LeathServer(const std::string path, const uint8_t id, const leath_server_share_t stored_share) : server_dir(path), server_id(id), server_share(stored_share){
    
}

std::unique_ptr<LeathServer> LeathServer::construct_from_directory (const std::string dir_path, const uint8_t  server_id, const int bits){
    if (!is_directory(dir_path))
    {
        throw std::runtime_error(dir_path + ": not a directory");
    }

    std::string server_share_path = dir_path + "/server_share_" + std::to_string(server_id);
    std::string server_input_path = dir_path + "/input_" + std::to_string(server_id);
    std::string server_triple_path = dir_path + "/triple_" + std::to_string(server_id);

    if (!is_file(server_share_path))
    {
        throw std::runtime_error("Missing server share file");
    }

    // if (!is_file(server_input_path))
    // {
    //     throw std::runtime_error("Missing server input file");
    // }

    // if (!is_file(server_triple_path))
    // {
    //     throw std::runtime_error("Missing server triple file");
    // }

    // restore client_share from file
    std::ifstream server_share_in(server_share_path.c_str(), std::ios::binary);
    std::stringstream server_share_stream;
    server_share_stream << server_share_in.rdbuf();

    leath_server_share_t stored_server_share;
    ub::convert(stored_server_share, mem_t::from_string(server_share_stream.str())); // set client_share !

    return std::unique_ptr<LeathServer>(new LeathServer(dir_path, server_id, stored_server_share));
}

std::unique_ptr<LeathServer> LeathServer::init_in_directory (const std::string dir_path, const uint8_t  server_id, const int bits) {
        if (!is_directory(dir_path)) {
        throw std::runtime_error(dir_path + ": not a directory");
    }

    return std::unique_ptr<LeathServer>(new LeathServer(dir_path, server_id));
}

error_t LeathServer::set_server_share(const leath_server_share_t s_share) {
    error_t rv = 0;
    
    server_share = s_share;

    return 0;
}

error_t LeathServer::leath_setup_peer2_step1(mem_t session_id, int server_id, const leath_setup_message1_t &in, leath_setup_message2_t &out)
{
    error_t rv = 0;

    int paillier_size = 1024; //get_safe_paillier_bits(curve);

    if (in.N.get_bits_count() < paillier_size)
        return rv = error(E_CRYPTO);


std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();


    if (!mpc::ZK_PAILLIER_V_non_interactive(in.N, in.pi_RN, session_id))
        return rv = error(E_CRYPTO);

std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for RN verification:"  << duration << " ms"  <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));



    crypto::paillier_t paillier;
    paillier.create_pub(in.N);


begin = std::chrono::high_resolution_clock::now();

    if (!in.zk_paillier_zero.v(in.N, in.c_3, session_id, 1))
        return rv = error(E_CRYPTO);

    if (!in.zk_paillier_m.v(in.N, paillier.add_ciphers(in.c_1, in.c_2), bn_t(1), session_id, 1))
        return rv = error(E_CRYPTO);

    if (!in.zk_paillier_mult.v(in.N, in.c_1, in.c_2, in.c_3, session_id, 1))
        return rv = error(E_CRYPTO);

end = std::chrono::high_resolution_clock::now();
duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for RG proof:"  << duration << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));



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


begin = std::chrono::high_resolution_clock::now();

    out.pk_i = pk;
    out.zk_pdl_mult.p(curve, pk, in.c_1, out._c_i, paillier, server_share.h_1, server_share.h_2, server_share._N, session_id, 1, sk, r, r_r);

end = std::chrono::high_resolution_clock::now();
duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for RS proof:"  << duration << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


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

error_t LeathServer::leath_share_peer2_step1(mem_t session_id, const uint64_t vid, const leath_maced_share_t &in, leath_maced_share_t &out)
{
    // firstly add in with local keys_share
    out.share = in.share + server_share.keys_share;
    out.mac_share = in.mac_share;

    store_maced_share(vid, out);
    return 0;
}

error_t LeathServer::leath_share_peer2_step1(mem_t session_id, const leath_maced_share_with_VID_t &in, leath_maced_share_with_VID_t &out)
{
    // firstly add in with local keys_share
    out.val_id = in.val_id;
    out.maced_share.share = in.maced_share.share + server_share.keys_share;
    out.maced_share.mac_share = in.maced_share.mac_share;

    store_maced_share(out.val_id, out.maced_share);
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
    MODULO(N2) out.share = server_share.c_2.pow(tmp.share);
    out.mac_share = tmp.mac_share;

    // crypto::paillier_t p; 
    // p.create_pub(server_share.N);
    // bn_t test = p.mul_scalar(server_share.c_2, tmp.share);

    // assert(out.share == test);

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

error_t LeathServer::write_share() 
{
    error_t rv = 0;
    if (!is_directory(server_dir))
    {
        throw std::runtime_error(server_dir + ": not a directory");
    }

    std::string server_share_path = server_dir + "/" + "server_share_" + std::to_string(server_id);

    std::ofstream server_share_out(server_share_path.c_str());
    if (!server_share_out.is_open())
    {
        throw std::runtime_error(server_share_path + ": unable to write the client share");
    }

    server_share_out << ub::convert(server_share).to_string();
    server_share_out.close();

    return 0;
}

error_t LeathServer::store_maced_share( const uint64_t vid, const leath_maced_share_t& s ) {

    share_map[vid] = s;

    //FIXME: store (share, mac_share) to file

    return 0;
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