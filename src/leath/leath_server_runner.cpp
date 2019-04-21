#include "leath_server_runner.h"

using namespace mpc::leath;

namespace mpc {
    LeathServerImpl::LeathServerImpl(const std::string& path, uint8_t id): already_setup(false), server_id(id), current_step(1){
        //
        // server_.reset(new LeathServer(path, id));

        if (is_directory(path)) {
            server_ = LeathServer::construct_from_directory(path, server_id, 1024); //FIXME:   
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
        
        logger::log(logger::INFO)<< "SETUP RECEIVED." <<std::endl;
        if (already_setup) return grpc::Status::CANCELLED;

        {// atomic operation
            std::lock_guard<std::mutex> lock(mtx_);
            
            if (current_step == 1) {
                error_t rv;

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
                already_setup = true; 
            }
        }
        return grpc::Status::OK;
    }

    grpc::Status LeathServerImpl::share(grpc::ServerContext* context, const ShareRequestMessage* request, google::protobuf::Empty* response){
        // TODO: 
                
        return grpc::Status::OK;
    }

    grpc::Status LeathServerImpl::reconstruct(grpc::ServerContext* context,  const ReconstructRequestMessage* request, ReconstructReply* response) {
        // TODO: 
        
        return grpc::Status::OK;
    }  

    void run_leath_server(const std::string &address, uint8_t server_id,  const std::string& server_db_path, grpc::Server **server_ptr) {
        std::string server_address(address);
        LeathServerImpl service(server_db_path, server_id);
        
        grpc::ServerBuilder builder;
        builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
        builder.RegisterService(&service);
        std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
        std::cout << "INFO: " << "Server listening on " << server_address << std::endl;
        
        *server_ptr = server.get();
        
        server->Wait();
    }

} // namespace mpc