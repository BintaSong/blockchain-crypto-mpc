#include "leath_client.h"

using namespace ub;

namespace mpc
{
leath_client_share_t LeathClient::client_share = {0};
std::mutex LeathClient::client_share_mutx_;

LeathClient::LeathClient(std::string path, int server_number, int bits) : client_path(path), paillier_keysize(bits), number_of_server(server_number) 
{

}

error_t LeathClient::leath_setup_peer1_step1(mem_t session_id, leath_setup_message1_t &out)
{
    // printf("in leath_setup_peer1_step1: begin ");

    crypto::paillier_t paillier, _paillier;
    paillier.generate(paillier_keysize, true);
    _paillier.generate(paillier_keysize, true);

    client_share.paillier = paillier;
    out.N = client_share.N = paillier.get_N();

    // printf("in leath_setup_peer1_step1: \n\n %s\n\n", out.N.to_string().c_str());

    // auxulary value
    out._N = client_share._N = _paillier.get_N();
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
    MODULO(out.N)
    m1 = mu * paillier.get_p();
    MODULO(out.N)
    m2 = lambda * paillier.get_q();

    // bn_t s, m;
    // MODULO(out.N) s = m1 + m2;
    // MODULO(out.N) m = m1 * m2;
    // assert( s == bn_t(1));

    client_share.c_1 = out.c_1 = paillier.encrypt(m1, r_1);
    client_share.c_2 = out.c_2 = paillier.encrypt(m2, r_2);

    client_share.x_1 = m1;
    client_share.x_2 = m2;

    out.c_3 = paillier.encrypt(0, r_3);
    // assert(paillier.decrypt(out.c_3).is_zero());

    out.zk_paillier_m.p(out.N, paillier.add_ciphers(out.c_1, out.c_2), bn_t(1), session_id, 1, r_1 * r_2);
    out.zk_paillier_zero.p(out.N, out.c_3, session_id, 1, r_3);
    out.zk_paillier_mult.p(out.N, out.c_1, out.c_2, out.c_3, session_id, 1, m1, m2, bn_t(0), r_1, r_2, r_3);

    client_share.mac_key = 0;// TODO: set mac key to zero!

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

error_t LeathClient::leath_setup_peer1_step3(mem_t session_id, int server_id, leath_setup_message3_t &out) {
    
    out.mac_key_share = bn_t::rand(client_share.N);

    client_share_mutx_.lock();
    MODULO(client_share.N) client_share.mac_key += out.mac_key_share;
    client_share_mutx_.unlock();

    return 0;
}


//----------client share step function----------------
error_t LeathClient::leath_share_peer1_step1(mem_t session_id, const bn_t raw_data, std::vector<leath_maced_share_t>& out) {

    return split_data_mac(raw_data,  out);
}
error_t LeathClient::leath_share_peer1_step1(mem_t session_id, uint64_t vid, const bn_t raw_data, std::vector<leath_maced_share_with_VID_t> &out) {
    return split_data_mac_with_VID(vid, raw_data, out);
}

error_t LeathClient::leath_reconstruct_peer1_step1(mem_t session_id, const uint64_t vid, const std::vector<leath_maced_share_t>& in, bn_t &data) {

    return reconstruct_data_mac(in, data);
}
error_t LeathClient::leath_reconstruct_peer1_step1(mem_t session_id, const std::vector<leath_maced_share_with_VID_t>& in, bn_t &data) {

    return reconstruct_data_mac_with_VID(in, data);
}

bn_t LeathClient::get_mac_key()
{
    return client_share.mac_key;
}

// error_t LeathClient::get_mac_key_share( const int number_of_server, std::vector<bn_t>& mac_key_shares )
// {
    
//     if (number_of_server < 2)
//     {
//         logger::log(logger::ERROR) << "Number of server must >= 2!" << std::endl;
//         return error(E_BADARG);
//     }

//     bn_t N = client_share.paillier.get_N();
//     bn_t tmp = client_share.mac_key;

//     for (int i = 0; i < number_of_server - 1; i++)
//     {
//         bn_t mac_share_i = bn_t::rand(N);
//         mac_key_shares.push_back(mac_share_i);
//         MODULO(N)
//         tmp = tmp - mac_share_i;
//     }
//     mac_key_shares.push_back(tmp);
//     return 0;
// }

bn_t LeathClient::get_partial_data(const bn_t raw_data)
{ 
    // partial_data = raw_data * crt(1, 0) + keys_share
    bn_t partial_data;
    MODULO(client_share.N) partial_data = raw_data * client_share.x_2 + client_share.keys_share;

    return partial_data;
}

error_t LeathClient::split_data(const bn_t raw_data, std::vector<bn_t>& _enhanced_data_shares)
{
    error_t rv = 0;
    if (number_of_server < 2)
    {
        logger::log(logger::ERROR) << "Number of server must >= 2!" << std::endl;
        return rv = error(E_BADARG);
    }
    // firstly make it to Zn
    bn_t tmp = get_partial_data(raw_data);

    for (int i = 0; i < number_of_server - 1; i++)
    {
        bn_t share_i = bn_t::rand(client_share.N);
        _enhanced_data_shares.push_back(share_i);
        MODULO(client_share.N)  tmp = tmp - share_i;
    }
    _enhanced_data_shares.push_back(tmp);

    return 0;
}

bn_t LeathClient::reconstruct_data( const std::vector<bn_t>& data_shares) 
{ 
    //_data = crt(raw_data, 0)
    if (data_shares.size() != number_of_server)
    {
        logger::log(logger::ERROR) << "Number of server must not match with share number" << std::endl;
        exit(-1);
    }
    bn_t raw_data = 0, data = 0;
    for(auto& s : data_shares) {
        MODULO(client_share.N) data += s;
    }
    // get raw data in Zp slot
    raw_data = data % client_share.paillier.get_p(); 

    return raw_data;
}

bool LeathClient::check_data(const bn_t data, const bn_t mac)
{
    bn_t tmp;
    MODULO(client_share.N) tmp = data * client_share.mac_key;
    if ( tmp != mac) {
        return false;
    }
    return true;
}

error_t LeathClient::split_data_mac(const bn_t raw_data, std::vector<leath_maced_share_t>& data_mac_shares){
    error_t rv = 0;
    if (number_of_server < 2)
    {
        logger::log(logger::ERROR) << "Number of server must >= 2!" << std::endl;
        return rv = error(E_BADARG);
    }

    bn_t data = get_partial_data(raw_data);
    bn_t mac;
    MODULO(client_share.N) mac = data * client_share.mac_key;

    for (int i = 0; i < number_of_server - 1; i++)
    {
        leath_maced_share_t maced_share_i;

        maced_share_i.share = bn_t::rand(client_share.N);
        maced_share_i.mac_share = bn_t::rand(client_share.N);

        data_mac_shares.push_back(maced_share_i);

        MODULO(client_share.N)  data = data - maced_share_i.share ;
        MODULO(client_share.N)  mac = mac - maced_share_i.mac_share ;
    }
    // push the final shares and mac share
    data_mac_shares.push_back({data, mac});

    return 0;
}


error_t LeathClient::split_data_mac_with_VID(const uint64_t vid, const bn_t raw_data, std::vector<leath_maced_share_with_VID_t>& data_mac_shares){
    error_t rv = 0;
    if (number_of_server < 2)
    {
        logger::log(logger::ERROR) << "Number of server must >= 2!" << std::endl;
        return rv = error(E_BADARG);
    }
    bn_t mac, data = get_partial_data(raw_data);
    MODULO(client_share.N) mac = data * client_share.mac_key;

    for (int i = 0; i < number_of_server - 1; i++)
    {
        leath_maced_share_with_VID_t maced_share_i;
        maced_share_i.val_id = vid;
        maced_share_i.maced_share = {bn_t::rand(client_share.N), bn_t::rand(client_share.N)};

        data_mac_shares.push_back(maced_share_i);

        MODULO(client_share.N)  data = data - maced_share_i.maced_share.share ;
        MODULO(client_share.N)  mac = mac - maced_share_i.maced_share.mac_share ;
    }
    // push the final shares and mac share
    data_mac_shares.push_back({vid, {data, mac}});

    return 0;
}

error_t LeathClient::reconstruct_data_mac(const std::vector<leath_maced_share_t>& data_mac_shares, bn_t& data){
    error_t rv = 0;

    if (number_of_server != data_mac_shares.size())
    {
        logger::log(logger::ERROR) << "Number of server not match with share number" << std::endl;
        return rv = error(E_BADARG);
    }
    bn_t data_tmp = 0, mac_tmp = 0;
    for (int i = 0; i < number_of_server; i++)
    {
        MODULO(client_share.N) data_tmp += data_mac_shares[i].share;
        MODULO(client_share.N) mac_tmp += data_mac_shares[i].mac_share;
    }

    rv = check_data(data_tmp, mac_tmp);
    if (rv != 0) {
        logger::log(logger::ERROR) << "reconstruct_data_mac(): mac check failed!" << std::endl;
        return rv;
    }

    // set the correct dara
    data = data_tmp % client_share.paillier.get_p();
    return 0;
}

error_t LeathClient::reconstruct_data_mac_with_VID(const std::vector<leath_maced_share_with_VID_t>& data_mac_shares, bn_t& data){
    error_t rv = 0;

    if (number_of_server != data_mac_shares.size())
    {
        logger::log(logger::ERROR) << "Number of server not match with share number" << std::endl;
        return rv = error(E_BADARG);
    }
    bn_t data_tmp = 0, mac_tmp = 0;
    for (int i = 0; i < number_of_server; i++)
    {
        MODULO(client_share.N) data_tmp += data_mac_shares[i].maced_share.share;
        MODULO(client_share.N) mac_tmp += data_mac_shares[i].maced_share.mac_share;
    }

    rv = check_data(data_tmp, mac_tmp);
    if (rv != 0) {
        logger::log(logger::ERROR) << "reconstruct_data_mac(): mac check failed!" << std::endl;
        return rv;
    }

    // set the correct dara
    data = data_tmp % client_share.paillier.get_p();
    return 0;
}

} // namespace mpc