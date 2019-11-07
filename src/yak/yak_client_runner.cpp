#include "yak_client_runner.h"

#include <grpc/grpc.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

namespace mpc {

YakClientRunner::YakClientRunner(const std::string peer_net_address, const std::string channel_addr) {
    std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(peer_net_address, grpc::InsecureChannelCredentials()));
    stub_ = yak::YakRPC::NewStub(channel);
    
    yak_channel_info_t info;
    get_channel_info(channel_addr, info);
    
    client_ = std::unique_ptr<YakClient>(new YakClient(info.my_addr, info.peer_addr));
}

error_t YakClientRunner::AKE(const ecc_point_t my_pk, const bn_t my_sk) {
    error_t rv = 0;
    
    yak_msg_t out, rec;    
    client_->yak_peer1_step1(ub::mem_t::from_string("test_session"), out);
    
    grpc::ClientContext context;
    yak::YakMessage request;
    yak::YakMessage response;

    request.set_e(ub::convert(out.eph).to_string());
    request.set_zkp(ub::convert(out.eph_zkp).to_string());
    request.set_pk(ub::convert(out.pk).to_string());

    grpc::Status status = stub_->AKE(&context, request, &response);
    if (!status.ok())
    {
        logger::log(logger::ERROR) << "RPC failed." << std::endl;
        return ub::error(E_UNAVAILABLE);
    }

    ub::convert(rec.eph, mem_t::from_string(response.e()));
    ub::convert(rec.eph_zkp, mem_t::from_string(response.zkp()));
    ub::convert(rec.pk, mem_t::from_string(response.pk()));

    rv = client_->yak_peer1_step2(ub::mem_t::from_string("test_session"), my_pk, my_sk, rec);
    if (rv != 0)
    {   
        logger::log(logger::ERROR) << "Check message failed." << std::endl;
        return ub::error(E_BADARG);
    }
}

void run_leath_client(){
    
}

} // namespace mpc
