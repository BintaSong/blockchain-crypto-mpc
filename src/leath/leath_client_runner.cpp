#include "leath_client_runner.h"


#include <grpc/grpc.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

namespace mpc {
    LeathClientRunner::LeathClientRunner(const std::vector<std::string>& addresses, const std::string client_path): current_step(1), already_setup(false), abort(false) 
    {
        for(auto& address : addresses) {
            std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
            stub_vector.push_back( std::move(leath::LeathRPC::NewStub(channel)) );
        }       
    }

    void LeathClientRunner::setup() {

        if (already_setup) {
            std::cout<< "ERROR: " << "Setup is already finished!" <<std::endl;
            return ;
        }
        leath_setup_message1_t out1;
        client_->leath_setup_peer1_step1(mem_t::from_string("setup_session"), out1);

        

        auto p2p_setup = [this, &out1](uint8_t id) {

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
        };

        std::vector<std::thread> threads;

        for (uint8_t t = 0; t < number_of_servers; t++) {
            threads.push_back( std::thread(p2p_setup, t) );
        }
        for (auto& t : threads) {
            t.join();
        }
    }

}