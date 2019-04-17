
#pragma once
#include "mpc_leath.h"

#include <iostream>
#include <mutex>

namespace mpc
{

class LeathServer
{
public:
    LeathServer(std::string path, int32_t id);

    // server setup step functions
    error_t leath_setup_peer2_step1(mem_t session_id, int server_id, ecc_point_t pk, bn_t sk, const leath_setup_message1_t &in, leath_setup_message2_t &out);

private:
    int32_t server_id;
    std::string server_path;

    leath_server_share_t server_share;
    std::mutex server_share_mutx_;
};

} //namespace mpc