#include "leath_server_runner.h"

using namespace mpc::leath;

namespace mpc {
    LeathServerImpl::LeathServerImpl(const std::string& path, const uint8_t id): already_setup(false), server_id(id), current_step(1){
        //
        // server_.reset(new LeathServer(path, id));

        if (is_directory(path)) {
            server_ = LeathServer::construct_from_directory(path, server_id, 1024); //FIXME:
            already_setup = true;

        }else if (exists(path)){
            throw std::runtime_error(path + ": not a directory");
        }else{      
            // FIXME: the first time run only create directory, nothing else!
            if (!create_directory(path, (mode_t)0700)) {
                throw std::runtime_error(path + ": unable to create directory");
            }
            server_ = LeathServer::init_in_directory(path, server_id, 1024);
        }
    }

    grpc::Status LeathServerImpl::setup(grpc::ServerContext* context, const SetupMessage* request, SetupMessage* response) {
        error_t rv = 0;

        logger::log(logger::INFO)<< "SETUP RECEIVED." <<std::endl;
        if (already_setup) return grpc::Status::CANCELLED;

time_t now = time(0); 
logger::log(logger::INFO)<< "Current time:"  << now  << " s" <<std::endl;

        {// atomic operation
            //std::lock_guard<std::mutex> lock(mtx_);
            
            if (current_step == 1) {
                // received message id does not match current step
                if (request->msg_id() != 1) return grpc::Status::CANCELLED;
                
                // convert msg to leath_setup_message1_t
                leath_setup_message1_t in;
                ub::convert(in, mem_t::from_string(request->msg()));

                // perform server-sid compuation
                leath_setup_message2_t out;
                rv = server_->leath_setup_peer2_step1(mem_t::from_string("setup_session"), server_->get_id(), in, out);
                if (rv != 0) return grpc::Status::CANCELLED;

                // response client 
                response->set_msg_id(2);
                response->set_msg(ub::convert(out).to_string());

                current_step++;
                // already_setup = true; 
            }
            else if (current_step == 2) {
                // if sever step is 2, then client step must be 3!
                if (request->msg_id() != 3) return grpc::Status::CANCELLED;
                
                // convert msg to leath_setup_message1_t
                leath_setup_message3_t in3;
                ub::convert(in3, mem_t::from_string(request->msg()));

                rv = server_->leath_setup_peer2_step2(mem_t::from_string("setup_session"), server_->get_id(), in3);
                if (rv != 0) return grpc::Status::CANCELLED;

                // response client 
                response->set_msg_id(3);
                response->set_msg("OK");

                current_step++;
                already_setup = true; 
                server_->write_share();
            }
        }
        return grpc::Status::OK;
    }

    grpc::Status LeathServerImpl::share(grpc::ServerContext* context, const ShareRequestMessage* request, google::protobuf::Empty* response){

        leath_maced_share_t in, out;

        logger::log(logger::INFO) << "Received share..." << std::endl;
        
        ub::convert(in.share, mem_t::from_string(request->value_share()));
        ub::convert(in.mac_share, mem_t::from_string(request->mac_share()));

        server_->leath_share_peer2_step1(mem_t::from_string("share_session"), request->value_id(), in, out);  // from `in` to get complete share, and store `out`
        //server_->leath_share_peer2_step1(mem_t::from_string("share_session"), request->value_id(), in, out);  // from `in` to get complete share, and store `out`
        logger::log(logger::INFO) << "...end share." << std::endl;
        return grpc::Status::OK;
    }

    grpc::Status LeathServerImpl::reconstruct(grpc::ServerContext* context,  const ReconstructRequestMessage* request, ReconstructReply* response) {
        error_t rv = 0;
        
        logger::log(logger::INFO) << "Received reconstruct..." << std::endl;

        leath_maced_share_t out;
        rv =  server_->leath_reconstruct_peer2_step1(mem_t::from_string("reconstruction_session"), request->value_id(), out);
        if (rv != 0 ) {
            return grpc::Status::CANCELLED;
        }

        response->set_value_id(request->value_id());
        response->set_value_share(out.share.to_string());
        response->set_mac_share(out.mac_share.to_string());

        logger::log(logger::INFO) << "...end reconstruct." << std::endl;

        return grpc::Status::OK;
    }  

    void run_leath_server(const std::string &address, uint8_t server_id,  const std::string& server_path, grpc::Server **server_ptr) {
        std::string server_address(address);
        LeathServerImpl service(server_path + std::to_string(server_id), server_id);
        
        grpc::ServerBuilder builder;
        builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
        builder.RegisterService(&service);
        std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
        std::cout << "INFO: " << "Server listening on " << server_address << std::endl;
        
        *server_ptr = server.get();
        
        server->Wait();
    }

} // namespace mpc