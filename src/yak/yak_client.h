#pragma once

#include "yak_common.h"

namespace mpc
{
    class YakClient{
        public:
            YakClient(const std::string _my_pk, const std::string _my_sk, const std::string _my_addr, const std::string _peer_address);
            error_t yak_peer1_step1(mem_t session_id, yak_msg_t &out);
            error_t yak_peer1_step2(mem_t session_id, const yak_msg_t &in, ecc_point_t &result);

        private:
            ecc_point_t my_pk;
            bn_t my_sk, my_esk;
            std::string my_addr, peer_addr;
    };
} // namespace mpc

