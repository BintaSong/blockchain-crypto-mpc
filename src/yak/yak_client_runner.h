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
        YakClientRunner(const std::string peer_net_address, const std::string channel_addr, const std::string my_pk_hex, const std::string my_sk_hex);
        error_t AKE();

      private:
        std::unique_ptr<yak::YakRPC::Stub> stub_;
        std::unique_ptr<YakClient> client_;
        
    }; // class YakClientRunner

    void run_leath_client();

} //namespace mpc

