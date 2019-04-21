#include "leath_client_runner.h"


#include <grpc/grpc.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

namespace mpc {
    LeathClientRunner::LeathClientRunner(const std::vector<std::string>& addresses, const std::string client_path): client_dir(client_path), current_step(1), already_setup(false), abort(false) 
    {
        for(auto& address : addresses) {
            std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
            stub_vector.push_back( (leath::LeathRPC::NewStub(channel)) );
        }

        number_of_servers = addresses.size();
        
        // client_.reset( new LeathClient(client_path, number_of_servers, 1024) );

        if (is_directory(client_path)) {
            client_ = LeathClient::construct_from_directory(client_path, number_of_servers, 1024);   
        }else if (exists(client_path)){
            throw std::runtime_error(client_path + ": not a directory");
        }else{      
            // FIXME: the first time run only create directory, nothing else!
            if (!create_directory(client_path, (mode_t)0700)) {
                throw std::runtime_error(client_path + ": unable to create directory");
            }
            client_ = LeathClient::init_in_directory(client_path, number_of_servers, 1024);
        }
    }

    void LeathClientRunner::setup() {
        logger::log(logger::INFO)<< "Setup begins ... "  <<std::endl;

        if (already_setup) {
            logger::log(logger::ERROR)<< "Setup is already finished!" <<std::endl;
            return ;
        }
        leath_setup_message1_t out1;
        client_->leath_setup_peer1_step1(mem_t::from_string("setup_session"), out1);

        logger::log(logger::INFO)<< "Before thread"  <<std::endl;

        int8_t id = 0;
        auto p2p_setup = [this, &out1](uint8_t id) {
            
            logger::log(logger::INFO)<< "Thread " << (int)id << " begins"  <<std::endl;

            grpc::ClientContext context;
            leath::SetupMessage request, response;
            grpc::Status status;
            
            request.set_msg_id(current_step);
            request.set_msg( ub::convert(out1).to_string() );
            status = stub_vector[id]->setup(&context, request, &response);
            if (!status.ok()) {
                logger::log(logger::ERROR) << "Setup for server "<< id << " failed." <<std::endl;
                return ;
            }
            
            if (response.msg_id() != 2) {
                logger::log(logger::ERROR) << "Received message not matching current step." <<std::endl;
                return ;
            }

            leath_setup_message2_t in;
            ub::convert(in, mem_t::from_string(response.msg()));
            client_->leath_setup_peer1_step2(mem_t::from_string("setup_session"), id, in);

            logger::log(logger::INFO)<< "Thread " << (int)id << " done." <<std::endl;
        };

        std::vector<std::thread> threads;

        for (uint8_t t = 0; t < number_of_servers; t++) {
            threads.push_back( std::thread(p2p_setup, t) );
        }
        for (auto& t : threads) {
            t.join();
        }

        // in the end, store client share !
        already_setup = true;
        client_->write_share();
    } //setup



}