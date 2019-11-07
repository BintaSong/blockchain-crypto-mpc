#pragma once

#include "yak_common.h"

namespace mpc
{
    class YakServer{
        public:
            YakServer(const ecc_point_t _my_pk, const bn_t _my_sk, const std::string _my_addr, const std::string _peer_address);
            error_t yak_peer2_step1(const mem_t session_id, const yak_msg_t in, yak_msg_t &out);

        private:
            ecc_point_t my_pk;
            bn_t my_sk;
            std::string my_addr, peer_addr;
    };
} // namespace mpc