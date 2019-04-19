
#pragma once
#include "mpc_leath.h"

#include <mutex>

namespace mpc
{

class LeathClient
{
public:
    LeathClient(std::string path, int bits);

    //----------client setup step functions---------------
    error_t leath_setup_peer1_step1(mem_t session_id, leath_setup_message1_t &out);
    error_t leath_setup_peer1_step2(mem_t session_id, int server_id, const leath_setup_message2_t &in);
    error_t leath_setup_peer1_step3(mem_t session_id, int server_id, leath_setup_message3_t &out);

    //----------client share step function----------------
    error_t leath_share_peer1_step1(mem_t session_id, leath_maced_share_t &out);

    //----------client reconstruct step function----------
    error_t leath_reconstruct_peer1_step1(mem_t session_id, const uint64_t vid, const leath_maced_share_t in, leath_maced_share_t &out);
    error_t leath_reconstruct_peer1_step1(mem_t session_id, const leath_maced_share_with_VID_t in, leath_maced_share_with_VID_t &out);

// ----------------------------
    bn_t get_mac_key();
    error_t get_mac_key_share( const int number_of_server, std::vector<bn_t>& mac_key_shares );

    bn_t get_partial_data(const bn_t raw_data);

    error_t split_data(const bn_t data, int number_of_server, std::vector<bn_t>& data_shares);
    error_t split_data_mac(const bn_t data, int number_of_server, std::vector<leath_maced_share_t>& data_mac_shares);

    bn_t reconstruct_data(const int number_of_server, const std::vector<bn_t>& data_shares);  
    error_t reconstruct_data_mac(const int number_of_server, const std::vector<leath_maced_share_t>& data_mac_shares, bn_t& data);

    bool check_data(const bn_t data, const bn_t mac); 

private:
    bool is_setup; // TODO: depends on if path has remaining information
    int paillier_keysize; 
    std::string client_path;

    static leath_client_share_t client_share;
    static std::mutex client_share_mutx_;
};

} //namespace mpc