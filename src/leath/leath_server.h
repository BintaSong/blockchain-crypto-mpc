
#pragma once
#include "mpc_leath.h"

#include <iostream>
#include <mutex>

namespace mpc
{

class LeathServer
{
public:
    LeathServer(std::string path, uint8_t id);// path may contain pk, sk information

    error_t leath_setup_peer2_step1(mem_t session_id, int server_id, const leath_setup_message1_t &in, leath_setup_message2_t &out);

    int32_t get_id();

private:
    uint8_t server_id;
    std::string server_path;

    leath_server_share_t server_share;
    std::mutex server_share_mutx_;

};

} //namespace mpc