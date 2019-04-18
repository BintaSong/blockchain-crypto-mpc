#include "leath_server_runner.h"

using namespace mpc::leath;

namespace mpc {
    LeathServerImpl::LeathServerImpl(const std::string& path, uint8_t id): already_setup(false), server_id(id), current_step(1){
        //
        server_.reset(new LeathServer(path, id));
    }

    grpc::Status LeathServerImpl::setup(grpc::ServerContext* context, const SetupMessage* request, SetupMessage* response) {
        
        if (already_setup) return grpc::Status::CANCELLED;

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
        }

        if (current_step == 2) already_setup = true; 

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