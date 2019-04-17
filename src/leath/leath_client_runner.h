#pragma once

#include "leath.pb.h"
#include "leath.grpc.pb.h"

#include "leath_client.h"

#include <memory>
#include <thread>
#include <grpc++/channel.h>

#include <mutex>
#include <condition_variable>

namespace mpc {
    class LeathClientRunner {
    public:    
        LeathClientRunner(const std::vector<std::string>& addresses, const std::string client_path);

        void setup();

    private:
        std::vector< std::unique_ptr<leath::LeathRPC::Stub>> stub_vector;
        std::unique_ptr<LeathClient> client_;

        int32_t current_step;
        int32_t number_of_servers;
        bool already_setup, abort;

    }; //class LeathClientRunner

    void run_leath_client();
} //namespace mpc

