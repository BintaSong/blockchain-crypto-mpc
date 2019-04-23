#pragma once

#include "leath.pb.h"
#include "leath.grpc.pb.h"

#include "leath_client.h"

#include "logger.h"

#include <memory>
#include <thread>
#include <grpc++/channel.h>

#include <mutex>
#include <condition_variable>

namespace mpc {
    class LeathClientRunner {
    public:    
        LeathClientRunner(const std::vector<std::string>& addresses, const std::string client_path, const int bits);

        void setup();
        void simple_setup();

        error_t share(const uint64_t val_id, const bn_t& val);

        error_t reconstruct(const uint64_t val_id, bn_t& raw_data);

    private:
        std::vector< std::unique_ptr<leath::LeathRPC::Stub>> stub_vector;
        std::unique_ptr<LeathClient> client_;
        std::string client_dir;

        int32_t current_step;
        int32_t number_of_servers;
        bool already_setup, abort;

    }; //class LeathClientRunner

    void run_leath_client();
} //namespace mpc

