#pragma once

#include "mpc_leath.h"


#include "leath.pb.h"
#include "leath.grpc.pb.h"

#include <string>
#include <memory>
#include <mutex>

#include <grpc++/server.h>
#include <grpc++/server_context.h>

namespace mpc {

    class LeathServerImpl final : public leath::LeathRPC::Service {
    public:
        explicit LeathServerImpl(const std::string& path, const int server_id);
        
        grpc::Status setup(grpc::ServerContext* context,
                           const leath::SetupMessage* request,
                           leath::SetupMessage* response) override;
                
        
    private:
        leath_server_share_t server_share;
        
        std::mutex mtx_;
    };
    
    void run_leath_server(const std::string &address, const std::string& server_db_path, grpc::Server **server_ptr);

} // namespace mpc