// Generated by the gRPC protobuf plugin.
// If you make any local change, they will be lost.
// source: leath.proto

#include "leath.pb.h"
#include "leath.grpc.pb.h"

#include <grpc++/impl/codegen/async_stream.h>
#include <grpc++/impl/codegen/async_unary_call.h>
#include <grpc++/impl/codegen/channel_interface.h>
#include <grpc++/impl/codegen/client_unary_call.h>
#include <grpc++/impl/codegen/method_handler_impl.h>
#include <grpc++/impl/codegen/rpc_service_method.h>
#include <grpc++/impl/codegen/service_type.h>
#include <grpc++/impl/codegen/sync_stream.h>
namespace mpc {
namespace leath {

static const char* LeathRPC_method_names[] = {
  "/mpc.leath.LeathRPC/setup",
  "/mpc.leath.LeathRPC/share",
  "/mpc.leath.LeathRPC/batch_share",
  "/mpc.leath.LeathRPC/reconstruct",
  "/mpc.leath.LeathRPC/batch_reconstruct",
  "/mpc.leath.LeathRPC/bulk_reconstruct",
};

std::unique_ptr< LeathRPC::Stub> LeathRPC::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  std::unique_ptr< LeathRPC::Stub> stub(new LeathRPC::Stub(channel));
  return stub;
}

LeathRPC::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel), rpcmethod_setup_(LeathRPC_method_names[0], ::grpc::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_share_(LeathRPC_method_names[1], ::grpc::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_batch_share_(LeathRPC_method_names[2], ::grpc::RpcMethod::CLIENT_STREAMING, channel)
  , rpcmethod_reconstruct_(LeathRPC_method_names[3], ::grpc::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_batch_reconstruct_(LeathRPC_method_names[4], ::grpc::RpcMethod::BIDI_STREAMING, channel)
  , rpcmethod_bulk_reconstruct_(LeathRPC_method_names[5], ::grpc::RpcMethod::SERVER_STREAMING, channel)
  {}

::grpc::Status LeathRPC::Stub::setup(::grpc::ClientContext* context, const ::mpc::leath::SetupMessage& request, ::mpc::leath::SetupMessage* response) {
  return ::grpc::BlockingUnaryCall(channel_.get(), rpcmethod_setup_, context, request, response);
}

::grpc::ClientAsyncResponseReader< ::mpc::leath::SetupMessage>* LeathRPC::Stub::AsyncsetupRaw(::grpc::ClientContext* context, const ::mpc::leath::SetupMessage& request, ::grpc::CompletionQueue* cq) {
  return new ::grpc::ClientAsyncResponseReader< ::mpc::leath::SetupMessage>(channel_.get(), cq, rpcmethod_setup_, context, request);
}

::grpc::Status LeathRPC::Stub::share(::grpc::ClientContext* context, const ::mpc::leath::ShareRequestMessage& request, ::google::protobuf::Empty* response) {
  return ::grpc::BlockingUnaryCall(channel_.get(), rpcmethod_share_, context, request, response);
}

::grpc::ClientAsyncResponseReader< ::google::protobuf::Empty>* LeathRPC::Stub::AsyncshareRaw(::grpc::ClientContext* context, const ::mpc::leath::ShareRequestMessage& request, ::grpc::CompletionQueue* cq) {
  return new ::grpc::ClientAsyncResponseReader< ::google::protobuf::Empty>(channel_.get(), cq, rpcmethod_share_, context, request);
}

::grpc::ClientWriter< ::mpc::leath::ShareRequestMessage>* LeathRPC::Stub::batch_shareRaw(::grpc::ClientContext* context, ::google::protobuf::Empty* response) {
  return new ::grpc::ClientWriter< ::mpc::leath::ShareRequestMessage>(channel_.get(), rpcmethod_batch_share_, context, response);
}

::grpc::ClientAsyncWriter< ::mpc::leath::ShareRequestMessage>* LeathRPC::Stub::Asyncbatch_shareRaw(::grpc::ClientContext* context, ::google::protobuf::Empty* response, ::grpc::CompletionQueue* cq, void* tag) {
  return new ::grpc::ClientAsyncWriter< ::mpc::leath::ShareRequestMessage>(channel_.get(), cq, rpcmethod_batch_share_, context, response, tag);
}

::grpc::Status LeathRPC::Stub::reconstruct(::grpc::ClientContext* context, const ::mpc::leath::ReconstructRequestMessage& request, ::mpc::leath::ReconstructReply* response) {
  return ::grpc::BlockingUnaryCall(channel_.get(), rpcmethod_reconstruct_, context, request, response);
}

::grpc::ClientAsyncResponseReader< ::mpc::leath::ReconstructReply>* LeathRPC::Stub::AsyncreconstructRaw(::grpc::ClientContext* context, const ::mpc::leath::ReconstructRequestMessage& request, ::grpc::CompletionQueue* cq) {
  return new ::grpc::ClientAsyncResponseReader< ::mpc::leath::ReconstructReply>(channel_.get(), cq, rpcmethod_reconstruct_, context, request);
}

::grpc::ClientReaderWriter< ::mpc::leath::ReconstructRequestMessage, ::mpc::leath::ReconstructReply>* LeathRPC::Stub::batch_reconstructRaw(::grpc::ClientContext* context) {
  return new ::grpc::ClientReaderWriter< ::mpc::leath::ReconstructRequestMessage, ::mpc::leath::ReconstructReply>(channel_.get(), rpcmethod_batch_reconstruct_, context);
}

::grpc::ClientAsyncReaderWriter< ::mpc::leath::ReconstructRequestMessage, ::mpc::leath::ReconstructReply>* LeathRPC::Stub::Asyncbatch_reconstructRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq, void* tag) {
  return new ::grpc::ClientAsyncReaderWriter< ::mpc::leath::ReconstructRequestMessage, ::mpc::leath::ReconstructReply>(channel_.get(), cq, rpcmethod_batch_reconstruct_, context, tag);
}

::grpc::ClientReader< ::mpc::leath::ReconstructReply>* LeathRPC::Stub::bulk_reconstructRaw(::grpc::ClientContext* context, const ::mpc::leath::ReconstructRangeMessage& request) {
  return new ::grpc::ClientReader< ::mpc::leath::ReconstructReply>(channel_.get(), rpcmethod_bulk_reconstruct_, context, request);
}

::grpc::ClientAsyncReader< ::mpc::leath::ReconstructReply>* LeathRPC::Stub::Asyncbulk_reconstructRaw(::grpc::ClientContext* context, const ::mpc::leath::ReconstructRangeMessage& request, ::grpc::CompletionQueue* cq, void* tag) {
  return new ::grpc::ClientAsyncReader< ::mpc::leath::ReconstructReply>(channel_.get(), cq, rpcmethod_bulk_reconstruct_, context, request, tag);
}

LeathRPC::Service::Service() {
  (void)LeathRPC_method_names;
  AddMethod(new ::grpc::RpcServiceMethod(
      LeathRPC_method_names[0],
      ::grpc::RpcMethod::NORMAL_RPC,
      new ::grpc::RpcMethodHandler< LeathRPC::Service, ::mpc::leath::SetupMessage, ::mpc::leath::SetupMessage>(
          std::mem_fn(&LeathRPC::Service::setup), this)));
  AddMethod(new ::grpc::RpcServiceMethod(
      LeathRPC_method_names[1],
      ::grpc::RpcMethod::NORMAL_RPC,
      new ::grpc::RpcMethodHandler< LeathRPC::Service, ::mpc::leath::ShareRequestMessage, ::google::protobuf::Empty>(
          std::mem_fn(&LeathRPC::Service::share), this)));
  AddMethod(new ::grpc::RpcServiceMethod(
      LeathRPC_method_names[2],
      ::grpc::RpcMethod::CLIENT_STREAMING,
      new ::grpc::ClientStreamingHandler< LeathRPC::Service, ::mpc::leath::ShareRequestMessage, ::google::protobuf::Empty>(
          std::mem_fn(&LeathRPC::Service::batch_share), this)));
  AddMethod(new ::grpc::RpcServiceMethod(
      LeathRPC_method_names[3],
      ::grpc::RpcMethod::NORMAL_RPC,
      new ::grpc::RpcMethodHandler< LeathRPC::Service, ::mpc::leath::ReconstructRequestMessage, ::mpc::leath::ReconstructReply>(
          std::mem_fn(&LeathRPC::Service::reconstruct), this)));
  AddMethod(new ::grpc::RpcServiceMethod(
      LeathRPC_method_names[4],
      ::grpc::RpcMethod::BIDI_STREAMING,
      new ::grpc::BidiStreamingHandler< LeathRPC::Service, ::mpc::leath::ReconstructRequestMessage, ::mpc::leath::ReconstructReply>(
          std::mem_fn(&LeathRPC::Service::batch_reconstruct), this)));
  AddMethod(new ::grpc::RpcServiceMethod(
      LeathRPC_method_names[5],
      ::grpc::RpcMethod::SERVER_STREAMING,
      new ::grpc::ServerStreamingHandler< LeathRPC::Service, ::mpc::leath::ReconstructRangeMessage, ::mpc::leath::ReconstructReply>(
          std::mem_fn(&LeathRPC::Service::bulk_reconstruct), this)));
}

LeathRPC::Service::~Service() {
}

::grpc::Status LeathRPC::Service::setup(::grpc::ServerContext* context, const ::mpc::leath::SetupMessage* request, ::mpc::leath::SetupMessage* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status LeathRPC::Service::share(::grpc::ServerContext* context, const ::mpc::leath::ShareRequestMessage* request, ::google::protobuf::Empty* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status LeathRPC::Service::batch_share(::grpc::ServerContext* context, ::grpc::ServerReader< ::mpc::leath::ShareRequestMessage>* reader, ::google::protobuf::Empty* response) {
  (void) context;
  (void) reader;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status LeathRPC::Service::reconstruct(::grpc::ServerContext* context, const ::mpc::leath::ReconstructRequestMessage* request, ::mpc::leath::ReconstructReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status LeathRPC::Service::batch_reconstruct(::grpc::ServerContext* context, ::grpc::ServerReaderWriter< ::mpc::leath::ReconstructReply, ::mpc::leath::ReconstructRequestMessage>* stream) {
  (void) context;
  (void) stream;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status LeathRPC::Service::bulk_reconstruct(::grpc::ServerContext* context, const ::mpc::leath::ReconstructRangeMessage* request, ::grpc::ServerWriter< ::mpc::leath::ReconstructReply>* writer) {
  (void) context;
  (void) request;
  (void) writer;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace mpc
}  // namespace leath

