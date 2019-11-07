#pragma once

#include "yak.pb.h"
#include "yak.grpc.pb.h"

#include "yak_client.h"
#include "yak_common.h"

#include "logger.h"

#include <memory>
#include <grpc++/channel.h>


namespace mpc {
    class YakClientRunner {
      public:    
        YakClientRunner(const std::string peer_net_address, const std::string channel_addr);
        error_t AKE(const ecc_point_t my_pk, const bn_t my_sk);

      private:
        std::unique_ptr<yak::YakRPC::Stub> stub_;
        std::unique_ptr<YakClient> client_;
        
    }; // class YakClientRunner

    void run_leath_client();

} //namespace mpc

