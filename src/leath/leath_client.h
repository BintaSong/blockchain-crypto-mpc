
#pragma once
#include "mpc_leath.h"

#include <mutex>

namespace mpc
{

class LeathClient
{
public:
    LeathClient(std::string path, int bits);

    // client setup step functions
    error_t leath_setup_peer1_step1(mem_t session_id, leath_setup_message1_t &out);
    error_t leath_setup_peer1_step2(mem_t session_id, int server_id, const leath_setup_message2_t &in);

private:
    int paillier_keysize; 
    std::string client_path;

    static leath_client_share_t client_share;
    static std::mutex client_share_mutx_;
};

} //namespace mpc