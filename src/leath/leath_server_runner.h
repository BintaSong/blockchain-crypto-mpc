#pragma once

#include "mpc_leath.h"
#include "leath_server.h"

#include "leath.pb.h"
#include "leath.grpc.pb.h"


#include <string>
#include <memory>
#include <mutex>

#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include <grpc++/security/server_credentials.h>


using namespace mpc::leath;

namespace mpc {

    class LeathServerImpl final : public leath::LeathRPC::Service {
    public:
        explicit LeathServerImpl(const std::string& path, uint8_t id);
        
        grpc::Status setup(grpc::ServerContext* context,
                           const SetupMessage* request,
                           SetupMessage* response) override;

        grpc::Status share(grpc::ServerContext* context,
                           const ShareRequestMessage* request,
                           google::protobuf::Empty* response) override;

        grpc::Status batch_share(grpc::ServerContext* context, 
                            grpc::ServerReader< leath::ShareRequestMessage>* reader, 
                            leath::batchShareReply* response) override; 

        grpc::Status reconstruct(grpc::ServerContext* context,
                           const ReconstructRequestMessage* request,
                           ReconstructReply* response) override;       
        
        grpc::Status batch_reconstruct(grpc::ServerContext* context, 
                            grpc::ServerReaderWriter<ReconstructReply, ReconstructRequestMessage>* stream) override;
    
        grpc::Status bulk_reconstruct(grpc::ServerContext* context, 
                        const leath::ReconstructRangeMessage* request, grpc::ServerWriter< ::mpc::leath::ReconstructReply>* writer) override;

        // grpc::Status bulk_reconstruct_parallel(grpc::ServerContext* context, 
        //               const leath::ReconstructRangeMessage* request, grpc::ServerWriter<leath::ReconstructReply>* writer) override;

    private:
        std::unique_ptr<LeathServer> server_;

        bool already_setup;
        ecc_point_t pk; bn_t sk;

        uint8_t server_id, current_step;

        std::mutex mtx_;
    };
    

    // template <typename T> SetupMessage struct_to_message(T &struct_msg, int step);

    void run_leath_server(const std::string &address, uint8_t server_id, const std::string& server_path, grpc::Server **server_ptr);

} // namespace mpc