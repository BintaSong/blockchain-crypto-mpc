#include "leath_client.h"

using namespace ub;

namespace mpc
{
leath_client_share_t LeathClient::client_share = {0};
std::mutex LeathClient::client_share_mutx_;

LeathClient::LeathClient(const std::string path, const int server_number, const int bits) : client_dir(path), paillier_keysize(bits), number_of_server(server_number)
{
}

std::unique_ptr<LeathClient> LeathClient::construct_from_directory(const std::string dir_path, const int number_of_servers, const int bits)
{
    if (!is_directory(dir_path))
    {
        throw std::runtime_error(dir_path + ": not a directory");
    }

    std::string client_share_path = dir_path + "/client_share";
    std::string client_input_path = dir_path + "/input";
    // std::string client_triple_path = dir_path + "/triple";

    if (!is_file(client_share_path))
    {
        throw std::runtime_error("Missing client share file");
    }

//FIXME: 
    // if (!is_file(client_input_path))
    // {
    //     throw std::runtime_error("Missing client input file");
    // }

    // restore client_share from file
    std::ifstream client_share_in(client_share_path.c_str(), std::ios::binary);
    std::stringstream client_share_stream;
    client_share_stream << client_share_in.rdbuf();
    ub::convert(LeathClient::client_share, mem_t::from_string(client_share_stream.str())); // set client_share !

    

    return std::unique_ptr<LeathClient>(new LeathClient(dir_path, number_of_servers, bits));
}

std::unique_ptr<LeathClient> LeathClient::init_in_directory(const std::string dir_path, const int number_of_servers, const int bits)
{
    if (!is_directory(dir_path)) {
        throw std::runtime_error(dir_path + ": not a directory");
    }
    
    return std::unique_ptr<LeathClient>(new LeathClient(dir_path, number_of_servers, bits));
}

error_t LeathClient::leath_setup_paillier_generation(){
    crypto::paillier_t paillier, _paillier;
    paillier.generate(paillier_keysize, true);
    _paillier.generate(paillier_keysize, true);

    client_share.paillier = paillier;
    client_share.p = paillier.get_p();
    client_share.q = paillier.get_q();
    client_share.N = paillier.get_N();
    client_share.N2 = client_share.N * client_share.N;

    // auxulary value
    client_share._N = _paillier.get_N();
    client_share.h_1 = bn_t::rand(client_share.N);
    client_share.h_2 = bn_t::rand(client_share.N);


    bn_t lambda, mu;
    bn_t r = eGCD(client_share.N, paillier.get_p(), paillier.get_q(), mu, lambda);
    assert(r == bn_t(1));

    bn_t r_1, r_2;
    r_1 = bn_t::rand(client_share.N);
    r_2 = bn_t::rand(client_share.N);
    // r_3 = bn_t::rand(client_share.N);

    bn_t m1, m2;
    m1 = mu * paillier.get_p();
    m2 = lambda * paillier.get_q();

    client_share.c_1 = paillier.encrypt(m1, r_1);
    client_share.c_2 = paillier.encrypt(m2, r_2);
    client_share.x_1 = m1;
    client_share.x_2 = m2;
    client_share.r_1 = r_1;
    client_share.r_2 = r_2;

    return 0;
}

error_t LeathClient::leath_setup_peer1_step1(mem_t session_id, leath_setup_message1_t &out)
{
    /* crypto::paillier_t paillier, _paillier;
    paillier.generate(paillier_keysize, true);
    _paillier.generate(paillier_keysize, true);

    client_share.paillier = paillier;
    out.N = client_share.N = paillier.get_N(); */

    // auxulary value
    out.N = client_share.N;
    out._N = client_share._N; // = _paillier.get_N();
    out.h_1 = client_share.h_1; // = bn_t::rand(out._N);
    out.h_2 = client_share.h_2; // = bn_t::rand(out._N);

    // assert(out.N == paillier.get_N());
std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();
  
    out.pi_RN = ZK_PAILLIER_P_non_interactive(out.N, client_share.paillier.get_phi_N(), session_id);

std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for RN proof:"  << duration  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

/*     bn_t lambda, mu;
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

    client_share.c_1 = out.c_1 = paillier.encrypt(m1, r_1);
    client_share.c_2 = out.c_2 = paillier.encrypt(m2, r_2);
    client_share.x_1 = m1;
    client_share.x_2 = m2;

    out.c_3 = paillier.encrypt(0, r_3); */

    out.c_1 = client_share.c_1;
    out.c_2 = client_share.c_2;

    bn_t r_3 = bn_t::rand(out.N);
    out.c_3 = client_share.paillier.encrypt(0, r_3);

begin = std::chrono::high_resolution_clock::now();

    out.zk_paillier_m.p(out.N, client_share.paillier.add_ciphers(out.c_1, out.c_2), bn_t(1), session_id, 1, client_share.r_1 * client_share.r_2);
    out.zk_paillier_zero.p(out.N, out.c_3, session_id, 1, r_3);
    out.zk_paillier_mult.p(out.N, out.c_1, out.c_2, out.c_3, session_id, 1, client_share.x_1, client_share.x_2, bn_t(0), client_share.r_1, client_share.r_2, r_3);

end = std::chrono::high_resolution_clock::now();
duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for RG proof:" << duration <<std::endl;

    client_share.mac_key = 0; // TODO: set mac key to zero!
    
    logger::log(logger::INFO) << "Init from dir, |N| =  " << client_share.N.get_bin_size() << std::endl; 

    return 0;
}

error_t LeathClient::leath_setup_peer1_step2(mem_t session_id, int server_id, const leath_setup_message2_t &in)
{
    error_t rv = 0;

    if (!in.zk_pdl_mult.v(in.pk_i.get_curve(), in.pk_i, client_share.paillier.get_N(), client_share.c_1, in._c_i, client_share.h_1, client_share.h_2, client_share._N, session_id, 1))
        return rv = error(E_CRYPTO);

    bn_t x_i = client_share.paillier.decrypt(in._c_i);

    if (server_id < 0)
        return rv = error(E_BADARG);

    ecurve_t curve = in.pk_i.get_curve();
    if (!curve)
        return rv = ub::error(E_BADARG);
    int bits = curve.bits();

    // FIXME: maybe return the share is better ?
    client_share_mutx_.lock();
    client_share.keys_share += x_i * bn_t(2).pow_mod(bn_t(bits * server_id), client_share.paillier.get_N());
    client_share_mutx_.unlock();

    return 0;
}

error_t LeathClient::leath_setup_peer1_step3(mem_t session_id, int server_id, leath_setup_message3_t &out)
{

    out.mac_key_share = bn_t::rand(client_share.N);

    client_share_mutx_.lock();
    MODULO(client_share.N)
    client_share.mac_key += out.mac_key_share;
    client_share_mutx_.unlock();

    return 0;
}

//----------client share step function----------------
error_t LeathClient::leath_share_peer1_step1(mem_t session_id, const bn_t raw_data, std::vector<leath_maced_share_t> &out)
{

    return split_data_mac(raw_data, out);
}

error_t LeathClient::leath_share_peer1_step1_callback(mem_t session_id, const uint64_t vid, const bn_t raw_data, std::function<void(uint64_t, leath_maced_share_with_VID_t)> post_back) 
{
    error_t rv = 0;

    std::vector<leath_maced_share_with_VID_t> out;
    rv = split_data_mac_with_VID_callback(vid, raw_data, post_back);
    if (rv != 0)
    {
        logger::log(logger::ERROR) << "leath_share_peer1_step1_callback(): split data eror" << std::endl;
        return rv = error(E_GENERAL);
    }

    return 0;
}

error_t LeathClient::leath_share_peer1_step1(mem_t session_id, uint64_t vid, const bn_t raw_data, std::vector<leath_maced_share_with_VID_t> &out)
{
    return split_data_mac_with_VID(vid, raw_data, out);
}

error_t LeathClient::leath_reconstruct_peer1_step1(mem_t session_id, const uint64_t vid, const std::vector<leath_maced_share_t> &cipher_in, bn_t &data)
{

    return reconstruct_data_mac(cipher_in, data);
}
error_t LeathClient::leath_reconstruct_peer1_step1(mem_t session_id, const std::vector<leath_maced_share_with_VID_t> &cipher_in, bn_t &data)
{

    return reconstruct_data_mac_with_VID(cipher_in, data);
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

bn_t LeathClient::get_partial_data(const bn_t raw_data) // partial_data = raw_data * crt(1, 0) + keys_share
{

    bn_t partial_data = 0;
    MODULO(client_share.N)
    partial_data = raw_data * client_share.x_2 + client_share.keys_share;
    // assert( client_share.x_2 % client_share.paillier.get_p() == 1);
    // bn_t tmp;
    // MODULO(client_share.N) tmp = (partial_data - client_share.keys_share);
    // assert( tmp % client_share.paillier.get_p() == raw_data);
    return partial_data;
}

// error_t LeathClient::split_data(const bn_t raw_data, std::vector<bn_t>& _enhanced_data_shares)
// {
//     error_t rv = 0;
//     if (number_of_server < 2)
//     {
//         logger::log(logger::ERROR) << "Number of server must >= 2!" << std::endl;
//         return rv = error(E_BADARG);
//     }
//     // firstly make it to Zn
//     bn_t tmp = get_partial_data(raw_data);

//     for (int i = 0; i < number_of_server - 1; i++)
//     {
//         bn_t share_i = bn_t::rand(client_share.N);
//         _enhanced_data_shares.push_back(share_i);
//         MODULO(client_share.N)  tmp = tmp - share_i;
//     }
//     _enhanced_data_shares.push_back(tmp);

//     return 0;
// }

// bn_t LeathClient::reconstruct_data( const std::vector<bn_t>& data_shares)
// {
//     //_data = crt(raw_data, 0)
//     if (data_shares.size() != number_of_server)
//     {
//         logger::log(logger::ERROR) << "Number of server must not match with share number" << std::endl;
//         exit(-1);
//     }
//     bn_t raw_data = 0, data = 0;
//     for(auto& s : data_shares) {
//         MODULO(client_share.N) data += s;
//     }
//     // get raw data in Zp slot
//     raw_data = data % client_share.paillier.get_p(); // TODO: do not use % again !!!!

//     return raw_data;
// }

error_t LeathClient::check_data(const bn_t e_, const bn_t mac)
{
    bn_t tmp = -1;
    MODULO(client_share.N)  tmp = (e_ * client_share.mac_key - mac);

    if (tmp != 0)
    {
        logger::log(logger::ERROR) << "check_data(): MAC Check Failed!" << std::endl;
        return error(E_AUTH);
    }

    return 0;
}

error_t LeathClient::split_data_mac(const bn_t raw_data, std::vector<leath_maced_share_t> &data_mac_shares)
{
    error_t rv = 0;
    if (number_of_server < 2)
    {
        logger::log(logger::ERROR) << "Number of server must >= 2!" << std::endl;
        return rv = error(E_BADARG);
    }

    bn_t data = get_partial_data(raw_data);
    bn_t mac;
    MODULO(client_share.N) mac = raw_data * client_share.x_2 * client_share.mac_key;

    for (int i = 0; i < number_of_server - 1; i++)
    {
        leath_maced_share_t maced_share_i;

        maced_share_i.share = bn_t::rand(client_share.N);
        maced_share_i.mac_share = bn_t::rand(client_share.N);

        data_mac_shares.push_back(maced_share_i);

        MODULO(client_share.N) data = data - maced_share_i.share;
        MODULO(client_share.N) mac = mac - maced_share_i.mac_share;
    }
    // push the last shares and mac share
    data_mac_shares.push_back({data, mac});

    return 0;
}

error_t LeathClient::split_data_mac_with_VID(const uint64_t vid, const bn_t raw_data, std::vector<leath_maced_share_with_VID_t> &data_mac_shares)
{
    error_t rv = 0;

    if (number_of_server < 2)
    {
        logger::log(logger::ERROR) << "Number of server must >= 2!" << std::endl;
        return rv = error(E_BADARG);
    }

    bn_t mac, data = get_partial_data(raw_data);
    // bn_t tmp1 = 0, tmp2 = 0;

    // MODULO(client_share.N) tmp1 = (data - client_share.keys_share);
    // assert(tmp == ((data - client_share.keys_share) % client_share.N));
    // logger::log(logger::INFO) << tmp1.to_string() << "\n\n" << ((data - client_share.keys_share) % client_share.N).to_string() << std::endl;
    // assert(tmp1 % client_share.paillier.get_p() == raw_data);

    // bn_t tmp = data;
    MODULO(client_share.N)
    mac = raw_data * client_share.x_2 * client_share.mac_key; // raw_data * crt(1, 0) * mac_key

    // rv = check_data(data - client_share.keys_share, mac);
    // assert(rv == 0);

    for (int i = 0; i < number_of_server - 1; i++)
    {
        leath_maced_share_with_VID_t maced_share_i;
        maced_share_i.val_id = vid;
        maced_share_i.maced_share = {bn_t::rand(client_share.N), bn_t::rand(client_share.N)};

        data_mac_shares.push_back(maced_share_i);

        MODULO(client_share.N)
        data = data - maced_share_i.maced_share.share;
        MODULO(client_share.N)
        mac = mac - maced_share_i.maced_share.mac_share;
    }
    // push the final shares and mac share
    data_mac_shares.push_back({vid, {data, mac}});

    return 0;
}

error_t LeathClient::split_data_mac_with_VID_callback(const uint64_t vid, const bn_t raw_data, std::function<void(uint64_t, leath_maced_share_with_VID_t)> post_back) {
    error_t rv = 0;

    if (number_of_server < 2)
    {
        logger::log(logger::ERROR) << "Number of server must >= 2!" << std::endl;
        return rv = error(E_BADARG);
    }

    bn_t mac, data = get_partial_data(raw_data);

    MODULO(client_share.N) mac = raw_data * client_share.x_2 * client_share.mac_key; // raw_data * crt(1, 0) * mac_key

    for (int i = 0; i < number_of_server - 1; i++)
    {
        leath_maced_share_with_VID_t maced_share_i;
        maced_share_i.val_id = vid;
        maced_share_i.maced_share = {bn_t::rand(client_share.N), bn_t::rand(client_share.N)};
        // post_back
        post_back(i, maced_share_i);

        MODULO(client_share.N)
        data = data - maced_share_i.maced_share.share;
        MODULO(client_share.N)
        mac = mac - maced_share_i.maced_share.mac_share;
    }
    // post_back
    post_back(number_of_server - 1, {vid, {data, mac}});

    return 0;
}

error_t LeathClient::reconstruct_data_mac(const std::vector<leath_maced_share_t> &cipher_maced_shares, bn_t &raw_data)
{
    error_t rv = 0;


    if (number_of_server != cipher_maced_shares.size())
    {
        logger::log(logger::ERROR) << "reconstruct_data_mac(): Number of server not match with share number" << std::endl;
        return rv = error(E_BADARG);
    }
    bn_t e_ = 1, mac_tmp = 0;
    for (int i = 0; i < number_of_server; i++)
    {
        MODULO(client_share.N2)
        e_ *= cipher_maced_shares[i].share; // FIXME: also can decrypt cipher_maced_shares[i].share, and add the decrypted plaintext together
        MODULO(client_share.N)
        mac_tmp += cipher_maced_shares[i].mac_share;
    }

    bn_t e_data = client_share.paillier.decrypt(e_);

    // logger::log(logger::INFO) << "***raw_data *** = " << raw_data.to_string() << std::endl;

    rv = check_data(e_data, mac_tmp);
    if (rv != 0)
    {
        logger::log(logger::ERROR) << "reconstruct_data_mac(): MAC Check Failed!" << std::endl;
        return rv;
    }

    bn_t p = client_share.paillier.get_p();
    // FIXME: **DO NOT** use MODULO(client_share.paillier.get_p())
    MODULO(p)    raw_data = e_data - 0;
    return 0;
}

// TODO: wrong !!!
error_t LeathClient::reconstruct_data_mac_with_VID(const std::vector<leath_maced_share_with_VID_t> &cipher_maced_shares, bn_t &raw_data)
{
    error_t rv = 0;

    bn_t N, N2;
    N = client_share.N;
    N2 = N * N;

    if (number_of_server != cipher_maced_shares.size())
    {
        logger::log(logger::ERROR) << "Number of server not match with share number" << std::endl;
        return rv = error(E_BADARG);
    }
    bn_t e_ = 1, mac_tmp = 0;
    for (int i = 0; i < number_of_server; i++)
    {
        MODULO(client_share.N)
        e_ *= cipher_maced_shares[i].maced_share.share;
        MODULO(client_share.N)
        mac_tmp += cipher_maced_shares[i].maced_share.mac_share;
    }

    // set the correct dara
    bn_t e_data = client_share.paillier.decrypt(e_);
    rv = check_data(e_data, mac_tmp);
    if (rv != 0)
    {
        logger::log(logger::ERROR) << "reconstruct_data_mac(): mac check failed!" << std::endl;
        return rv;
    }

    bn_t p = client_share.paillier.get_p();
    // FIXME: **DO NOT** use MODULO(client_share.paillier.get_p())
    MODULO(p)
    raw_data = e_data - 0;

    return 0;
}

error_t LeathClient::write_share()
{
    error_t rv = 0;
    if (!is_directory(client_dir))
    {
        throw std::runtime_error(client_dir + ": not a directory");
    }

    std::string client_share_path = client_dir + "/" + "client_share";

    std::ofstream client_share_out(client_share_path.c_str());
    if (!client_share_out.is_open())
    {
        throw std::runtime_error(client_share_path + ": unable to write the client share");
    }

    client_share_out << ub::convert(client_share).to_string();
    client_share_out.close();

    return 0;
}
} // namespace mpc