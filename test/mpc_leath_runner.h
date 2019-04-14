#pragma once

#include "mpc_leath.h"

// #include "leath.grpc.pb.h"

// #include <string>
// #include <memory>
// #include <mutex>

// #include <grpc++/server.h>
// #include <grpc++/server_context.h>

// namespace mpc{
//     class LeathImpl final : public Leath::Service {
//     public:
//         explicit LeathImpl(const std::string& path);
        
//         grpc::Status setup(grpc::ServerContext* context,
//                            const Leath::SetupMessage* request,
//                            google::protobuf::Empty* e) override;
        
//         grpc::Status search(grpc::ServerContext* context,
//                             const fast::SearchRequestMessage* request,
//                             grpc::ServerWriter<fast::SearchReply>* writer) override;
        
//         grpc::Status sync_search(grpc::ServerContext* context,
//                             const fast::SearchRequestMessage* request,
//                             grpc::ServerWriter<fast::SearchReply>* writer);
        
//         grpc::Status async_search(grpc::ServerContext* context,
//                                   const fast::SearchRequestMessage* request,
//                                   grpc::ServerWriter<fast::SearchReply>* writer);
        
//         grpc::Status update(grpc::ServerContext* context,
//                             const fast::UpdateRequestMessage* request,
//                             google::protobuf::Empty* e) override;
        
//         grpc::Status bulk_update(grpc::ServerContext* context,
//                                  grpc::ServerReader<fast::UpdateRequestMessage>* reader,
//                                  google::protobuf::Empty* e) override;
        
//         std::ostream& print_stats(std::ostream& out) const;

//         bool search_asynchronously() const;
//         void set_search_asynchronously(bool flag);
        
        
//     private:
//         static const std::string pk_file;
//         static const std::string pairs_map_file;

//         std::unique_ptr<FastServer> server_;
//         std::string storage_path_;
        
//         std::mutex update_mtx_;
        
//         bool async_search_;
//     };
    
//     SearchRequest message_to_request(const SearchRequestMessage* mes);
//     UpdateRequest message_to_request(const UpdateRequestMessage* mes);

//     void run_fast_server(const std::string &address, const std::string& server_db_path, grpc::Server **server_ptr, bool async_search);
// }