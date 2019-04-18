#include "leath_client_runner.h"


#include <grpc/grpc.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

namespace mpc {
    LeathClientRunner::LeathClientRunner(const std::vector<std::string>& addresses, const std::string client_path): current_step(1), already_setup(false), abort(false) 
    {
        // std::cout << "INFO:" << "In  LeathClientRunner::LeathClientRunner()." << std::endl;
        for(auto& address : addresses) {
            // std::cout << "INFO:" << "In  address for 1" << std::endl;
            std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
            // std::cout << "INFO:" << "In  address for 2" << std::endl;
            stub_vector.push_back( (leath::LeathRPC::NewStub(channel)) );
        }

        client_.reset( new LeathClient("TODO: test", 1024) );
    }

    void LeathClientRunner::setup() {
        std::cout << "INFO:" << "Setup begin 1" << std::endl;
        if (already_setup) {
            std::cout<< "ERROR: " << "Setup is already finished!" <<std::endl;
            return ;
        }
        leath_setup_message1_t out1;
        client_->leath_setup_peer1_step1(mem_t::from_string("setup_session"), out1);

        std::cout << "INFO:" << "In  setup for 2" << std::endl;

        int8_t id = 0;
        // auto p2p_setup = [this, &out1](uint8_t id) {
            std::cout << "INFO:" << "In  thread begin" << std::endl;
            grpc::ClientContext context;
            leath::SetupMessage request, response;
            grpc::Status status;
            
            request.set_msg_id(current_step);
            request.set_msg( ub::convert(out1).to_string() );
            status = stub_vector[id]->setup(&context, request, &response);
            if (!status.ok()) {
                std::cout<< "ERROR: " << "Setup for server "<< id << " failed." <<std::endl;
                return ;
            }
            
            if (response.msg_id() != 2) {
                 std::cout<< "ERROR: " << "Received message not match current step." <<std::endl;
                return ;
            }

            leath_setup_message2_t in;
            ub::convert(in, mem_t::from_string(response.msg()));
            client_->leath_setup_peer1_step2(mem_t::from_string("setup_session"), id, in);
            std::cout<< "INFO: " << "Thread " << id << " done." <<std::endl;
        // };

        // std::vector<std::thread> threads;

        // for (uint8_t t = 0; t < number_of_servers; t++) {
        //     threads.push_back( std::thread(p2p_setup, t) );
        // }
        // for (auto& t : threads) {
        //     t.join();
        // }
    }

}