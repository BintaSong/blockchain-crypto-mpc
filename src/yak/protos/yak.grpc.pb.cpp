// Generated by the gRPC protobuf plugin.
// If you make any local change, they will be lost.
// source: yak.proto

#include "yak.pb.h"
#include "yak.grpc.pb.h"

#include <grpc++/impl/codegen/async_stream.h>
#include <grpc++/impl/codegen/async_unary_call.h>
#include <grpc++/impl/codegen/channel_interface.h>
#include <grpc++/impl/codegen/client_unary_call.h>
#include <grpc++/impl/codegen/method_handler_impl.h>
#include <grpc++/impl/codegen/rpc_service_method.h>
#include <grpc++/impl/codegen/service_type.h>
#include <grpc++/impl/codegen/sync_stream.h>
namespace mpc {
namespace yak {

static const char* YakRPC_method_names[] = {
  "/mpc.yak.YakRPC/AKE",
};

std::unique_ptr< YakRPC::Stub> YakRPC::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  std::unique_ptr< YakRPC::Stub> stub(new YakRPC::Stub(channel));
  return stub;
}

YakRPC::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel), rpcmethod_AKE_(YakRPC_method_names[0], ::grpc::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status YakRPC::Stub::AKE(::grpc::ClientContext* context, const ::mpc::yak::YakMessage& request, ::mpc::yak::YakMessage* response) {
  return ::grpc::BlockingUnaryCall(channel_.get(), rpcmethod_AKE_, context, request, response);
}

::grpc::ClientAsyncResponseReader< ::mpc::yak::YakMessage>* YakRPC::Stub::AsyncAKERaw(::grpc::ClientContext* context, const ::mpc::yak::YakMessage& request, ::grpc::CompletionQueue* cq) {
  return new ::grpc::ClientAsyncResponseReader< ::mpc::yak::YakMessage>(channel_.get(), cq, rpcmethod_AKE_, context, request);
}

YakRPC::Service::Service() {
  (void)YakRPC_method_names;
  AddMethod(new ::grpc::RpcServiceMethod(
      YakRPC_method_names[0],
      ::grpc::RpcMethod::NORMAL_RPC,
      new ::grpc::RpcMethodHandler< YakRPC::Service, ::mpc::yak::YakMessage, ::mpc::yak::YakMessage>(
          std::mem_fn(&YakRPC::Service::AKE), this)));
}

YakRPC::Service::~Service() {
}

::grpc::Status YakRPC::Service::AKE(::grpc::ServerContext* context, const ::mpc::yak::YakMessage* request, ::mpc::yak::YakMessage* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace mpc
}  // namespace yak

