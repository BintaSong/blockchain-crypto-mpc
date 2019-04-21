#pragma once
#include "mpc_leath.h"

#include "utils.h"

#include <mutex>

namespace mpc
{

class LeathClient
{
public:
    LeathClient(const std::string path, const int server_number, const int bits);

    static std::unique_ptr<LeathClient> construct_from_directory (const std::string dir_path, const int number_of_servers, const int bits);
    static std::unique_ptr<LeathClient> init_in_directory(const std::string dir_path, const int number_of_servers, const int bits);

    //----------client setup step functions---------------
    error_t leath_setup_peer1_step1(mem_t session_id, leath_setup_message1_t &out);
    error_t leath_setup_peer1_step2(mem_t session_id, int server_id, const leath_setup_message2_t &in);
    error_t leath_setup_peer1_step3(mem_t session_id, int server_id, leath_setup_message3_t &out);

    //----------client share step function----------------
    error_t leath_share_peer1_step1(mem_t session_id, const bn_t raw_data, std::vector<leath_maced_share_t>& out);
    error_t leath_share_peer1_step1(mem_t session_id, uint64_t vid, const bn_t raw_data, std::vector<leath_maced_share_with_VID_t> &out);

    //----------client reconstruct step function----------
    error_t leath_reconstruct_peer1_step1(mem_t session_id, const uint64_t vid, const std::vector<leath_maced_share_t>& in, bn_t &data);
    error_t leath_reconstruct_peer1_step1(mem_t session_id, const std::vector<leath_maced_share_with_VID_t>& in, bn_t &data);


// ----------------------------
    bn_t get_mac_key();
    // error_t get_mac_key_share( const int number_of_server, std::vector<bn_t>& mac_key_shares );

    bn_t get_partial_data(const bn_t raw_data);

    // error_t split_data(const bn_t raw_data, std::vector<bn_t>& data_shares);
    error_t split_data_mac(const bn_t raw_data, std::vector<leath_maced_share_t>& data_mac_shares);
    error_t split_data_mac_with_VID(const uint64_t vid, const bn_t raw_data, std::vector<leath_maced_share_with_VID_t>& data_mac_shares);

    // bn_t reconstruct_data(const std::vector<bn_t>& data_shares);  
    error_t reconstruct_data_mac(const std::vector<leath_maced_share_t>& data_mac_shares, bn_t& raw_data);
    error_t reconstruct_data_mac_with_VID(const std::vector<leath_maced_share_with_VID_t>& data_mac_shares, bn_t& raw_data);

    error_t check_data(const bn_t data, const bn_t mac);

//----------some file interface-----------
    error_t write_share();

public:
    //bool is_setup; // TODO: depends on if path has remaining information
    std::string client_dir;
    int number_of_server, paillier_keysize;

    static leath_client_share_t client_share;
    static std::mutex client_share_mutx_;
};

} //namespace mpc