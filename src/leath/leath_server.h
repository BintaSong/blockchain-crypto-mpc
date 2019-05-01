#pragma once
#include "mpc_leath.h"

#include "thread_pool.h"

#include "utils.h"

#include <iostream>
#include <mutex>

namespace mpc
{

class LeathServer
{
public:
    LeathServer(const std::string path, const uint8_t id);// path may contain pk, sk information
    LeathServer(const std::string path, const uint8_t id, const leath_server_share_t stored_share);


    static std::unique_ptr<LeathServer> construct_from_directory (const std::string dir_path, const uint8_t  server_id, const int bits);
    static std::unique_ptr<LeathServer> init_in_directory(const std::string dir_path, const uint8_t  server_id, const int bits);

    error_t set_server_share(const leath_server_share_t s_share);

    // ------------------for setup------------------
    error_t leath_setup_peer2_step1(mem_t session_id, int server_id, const leath_setup_message1_t &in, leath_setup_message2_t &out);
    error_t leath_setup_peer2_step2(mem_t session_id, int server_id, const leath_setup_message3_t &in);

    //-------------------for share------------------
    // TODO: store the share locally !
    error_t leath_share_peer2_step1(mem_t session_id,  const uint64_t vid, const leath_maced_share_t &in, leath_maced_share_t &out);
    error_t leath_share_peer2_step1(mem_t session_id, const leath_maced_share_with_VID_t &in, leath_maced_share_with_VID_t &out);

    //-------------------for reconstruct------------
    // error_t leath_reconstruct_peer2_step1(mem_t session_id, const leath_maced_share_t &in, leath_maced_share_t &out);
    error_t leath_reconstruct_peer2_step1(mem_t session_id, const uint64_t vid, leath_maced_share_t &out);
    error_t leath_reconstruct_peer2_step1_parallel(mem_t session_id, const uint64_t begin_vid, const uint64_t end_vid, std::function<void(uint64_t, leath_maced_share_t)> post_callback);


    //-------------------computation on shares------
    leath_maced_share_t add_shares(const leath_maced_share_t s_1, const leath_maced_share_t s_2);
    leath_maced_share_t add_constant(const leath_maced_share_t s, const bn_t e);
    leath_maced_share_t multiply_constant(const leath_maced_share_t s, const bn_t e);
    // leath_maced_share_t multiply_shares(leath_maced_share_t share_1, leath_maced_share_t share_2);

    int32_t get_id();
    error_t write_share();

public:

    uint8_t server_id;
    std::string server_dir;

    leath_server_share_t server_share;
    std::mutex server_share_mutx_;

    // TODO: just for test !
    std::map<uint64_t, leath_maced_share_t> share_map;

    // TODO: how ot get?
    error_t get_maced_share(const uint64_t vid, leath_maced_share_t &s);
    error_t store_maced_share( const uint64_t vid, const leath_maced_share_t& s);

};

} //namespace mpc