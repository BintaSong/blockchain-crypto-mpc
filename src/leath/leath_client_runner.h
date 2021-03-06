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
        LeathClientRunner(const std::vector<std::string>& addresses, const uint64_t server_number, const std::string client_path, const int bits);
        // ~LeathClientRunner();
        
        //void generate_parameter();
        void pre_setup();
        void setup();
        void parallel_setup();
        void simple_setup();

        error_t share(const uint64_t val_id, const bn_t& val);
        error_t share_benchmark(uint64_t begin, uint64_t end);
        error_t batch_share_benchmark(uint64_t counter);


        error_t reconstruct(const uint64_t val_id, bn_t& raw_data);
        // error_t simple_reconstruct(const uint64_t val_id, bn_t& raw_data);
        // error_t reconstruct_benchmark(int shares_number);
        error_t bulk_reconstruct(const uint64_t begin, const uint64_t end);
        // void test_rpc();

        static std::mutex RS_mtx;

    private:
        // std::vector<std::string> addr_vector;
        // std::vector<std::shared_ptr<grpc::Channel>> channel_vector;
        std::vector< std::unique_ptr<leath::LeathRPC::Stub>> stub_vector;

        std::unique_ptr<LeathClient> client_;
        std::string client_dir;

        int32_t current_step;
        uint32_t number_of_servers;
        bool already_setup, abort;


        struct leath_share_writers_t{
            std::unique_ptr<grpc::ClientContext> context;
            std::unique_ptr<leath::batchShareReply> response;
            std::unique_ptr<grpc::ClientWriter<leath::ShareRequestMessage>> writer_;
            std::mutex mtx;
        };


        //grpc::Status setup_rpc(const int id, const leath::SetupMessage& request, leath::SetupMessage *response);
        //grpc::Status share_rpc(const int id, const leath::ShareRequestMessage& request);
        //grpc::Status reconstruct_rpc(const int id, const leath::ReconstructRequestMessage& request, leath::ReconstructReply *response);
    }; //class LeathClientRunner


    void run_leath_client();
} //namespace mpc

