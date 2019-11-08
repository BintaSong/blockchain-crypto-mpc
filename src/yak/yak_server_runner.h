#pragma once

#include "yak_server.h"
#include "yak_common.h"

#include "yak.pb.h"
#include "yak.grpc.pb.h"


#include <memory>
#include <mutex>

#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include <grpc++/security/server_credentials.h>


using namespace mpc::yak;

namespace mpc {

    class YakServerImpl final : public yak::YakRPC::Service {
        public:
            explicit YakServerImpl(const std::string& path, const std::string channel_addr, const std::string my_pk_hex, const std::string my_sk_hex){
                yak_channel_info_t info;
                get_channel_info(channel_addr, info);
    
                server_ = std::unique_ptr<YakServer>(new YakServer(my_pk_hex, my_sk_hex, info.my_addr, info.peer_addr));
            }

            grpc::Status AKE(grpc::ServerContext* context, const yak::YakMessage* request, yak::YakMessage* response){
                error_t rv = 0;
                yak_msg_t in, out;
                ecc_point_t dh;
                rv = server_->yak_peer2_step1(mem_t::from_string("test_session"), in, out, dh);
                if (rv != 0) 
                {
                    logger::log(logger::ERROR) << "RPC failed." << std::endl;   
                    return grpc::Status::CANCELLED; 
                }

                response->set_pk( ub::convert(out.pk).to_string() );
                response->set_e( ub::convert(out.eph).to_string() );
                response->set_zkp( ub::convert(out.eph_zkp).to_string() );

                return grpc::Status::OK;
            }
            
        private:
            std::unique_ptr<YakServer> server_;
    };
    
    void run_leath_server(const std::string &address, uint8_t server_id, const std::string& server_path, grpc::Server **server_ptr);

} // namespace mpc