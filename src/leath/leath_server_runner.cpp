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

        // logger::log(logger::INFO) << "Received share..." << std::endl;
        
        ub::convert(in.share, mem_t::from_string(request->value_share()));
        ub::convert(in.mac_share, mem_t::from_string(request->mac_share()));

        server_->leath_share_peer2_step1(mem_t::from_string("share_session"), request->value_id(), in, out);  // from `in` to get complete share, and store `out`
        //server_->leath_share_peer2_step1(mem_t::from_string("share_session"), request->value_id(), in, out);  // from `in` to get complete share, and store `out`
        // logger::log(logger::INFO) << "...end share." << std::endl;
        return grpc::Status::OK;
    }

    grpc::Status LeathServerImpl::batch_share(grpc::ServerContext* context, grpc::ServerReader< ShareRequestMessage>* reader, google::protobuf::Empty* response) {
        
        ShareRequestMessage mes;
        
        ThreadPool share_pool(4);

        auto share = [this](ShareRequestMessage *receive_msg) {
            leath_maced_share_t in, out;
            ub::convert(in.share, mem_t::from_string(receive_msg->value_share()));
            ub::convert(in.mac_share, mem_t::from_string(receive_msg->mac_share()));
            server_->leath_share_peer2_step1(mem_t::from_string("share_session"), receive_msg->value_id(), in, out);
        };

        while (reader->Read(&mes)) {
            share_pool.enqueue(share, &mes);
        }

        share_pool.join();
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

    grpc::Status LeathServerImpl::batch_reconstruct(grpc::ServerContext* context, grpc::ServerReaderWriter<ReconstructReply, ReconstructRequestMessage>* stream) {
        // TODO: 
        return  grpc::Status::OK;
    }
/*
grpc::Status LeathServerImpl::bulk_reconstruct(grpc::ServerContext* context, const leath::ReconstructRangeMessage* request, grpc::ServerWriter<leath::ReconstructReply>* writer) {
        //int threads_number = 2;
        error_t rv = 0;

        logger::log(logger::INFO) << "Received reconstruct." << std::endl;
        
        leath_maced_share_t out;
        double sum = 0.0, sum_com = 0.0;
        
std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();        
        for(uint64_t vid = request->begin_id(); vid < request->end_id(); vid++) {
            leath::ReconstructReply reply;

std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

            rv =  server_->leath_reconstruct_peer2_step1(mem_t::from_string("reconstruction_session"), vid, out);
            if (rv != 0 ) {
                logger::log(logger::INFO) << "bulk_reconstruct() error, vid: " << vid <<std::endl;
                return grpc::Status::CANCELLED;
            }

std::chrono::high_resolution_clock::time_point t3 = std::chrono::high_resolution_clock::now();
            reply.set_value_id(vid);
            reply.set_value_share(out.share.to_string());
            reply.set_mac_share(out.mac_share.to_string());
            writer->Write(reply);
std::chrono::high_resolution_clock::time_point t4 = std::chrono::high_resolution_clock::now();
sum_com += (double)std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();
sum += (double)std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count();
        }

logger::log(logger::INFO)<< "Time for bulk_reconstruct() computation time:"  << sum_com / (request->end_id() - request->begin_id())  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));
logger::log(logger::INFO)<< "Time for bulk_reconstruct() encoding & RPC time:"  << sum / (request->end_id() - request->begin_id())  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

std::chrono::high_resolution_clock::time_point t5 = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t1).count();
logger::log(logger::INFO)<< "Time for bulk_reconstruct() with Network:"  << duration / (request->end_id() - request->begin_id())  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

        return  grpc::Status::OK;
    }
*/

    grpc::Status LeathServerImpl::bulk_reconstruct(grpc::ServerContext* context, const leath::ReconstructRangeMessage* request, grpc::ServerWriter<leath::ReconstructReply>* writer) {
              
        error_t rv = 0;
        
        std::mutex writer_lock;
    
        auto post_callback = [&writer, &writer_lock](const uint64_t vid, const leath_maced_share_t &out)
        {
            leath::ReconstructReply reply;
            reply.set_value_id(vid);
            reply.set_value_share(out.share.to_string());
            reply.set_mac_share(out.mac_share.to_string());
            
            writer_lock.lock();
            writer->Write(reply);
            writer_lock.unlock();
        };

std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

        server_->leath_reconstruct_peer2_step1_parallel(mem_t::from_string("reconstruction_session"), request->begin_id(), request->end_id(), post_callback);
        
std::chrono::high_resolution_clock::time_point t5 = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t1).count();

logger::log(logger::INFO)<< "Time for PARALLEL bulk_reconstruct() with Network:"  << duration / (request->end_id() - request->begin_id())  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

        return  grpc::Status::OK;
    }

/*     grpc::Status LeathServerImpl::bulk_reconstruct(grpc::ServerContext* context, const leath::ReconstructRangeMessage* request, grpc::ServerWriter<leath::ReconstructReply>* writer) {
              
        error_t rv = 0;
        
        std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
        
        std::mutex writer_mutex;

        auto thread_reconstruct = [this, &writer, &writer_mutex, &request](uint64_t id, uint64_t step) {
            error_t rv = 0;
            leath_maced_share_t out;

            leath::ReconstructReply reply;
            // logger::log(logger::INFO)<< (int) id << ", 1" <<std::endl;

            for(uint64_t vid = id + request->begin_id(); vid < request->end_id(); vid += step){ 
                    
                rv =  server_->leath_reconstruct_peer2_step1(mem_t::from_string("reconstruction_session"), vid, out);

                if (rv != 0 ) {
                    logger::log(logger::ERROR) << "bulk_reconstruct() error, vid: " << vid <<std::endl;
                    return grpc::Status::CANCELLED;
                }

                logger::log(logger::INFO)<< (int)vid <<std::endl;

                // reply.set_value_id(vid);
                // reply.set_value_share(out.share.to_string());
                // reply.set_mac_share(out.mac_share.to_string());

                // logger::log(logger::INFO)<< (int) id << ", 3" <<std::endl;

                // writer_mutex.lock();
                // writer->Write(reply);
                // logger::log(logger::INFO)<< (int) id <<", 4" <<std::endl;
                // writer_mutex.unlock();
            }
            // logger::log(logger::INFO)<<"end." <<std::endl;
        };

    unsigned n_threads = std::thread::hardware_concurrency() - 1;

    std::vector<std::thread> threads;

logger::log(logger::INFO)<< "Received reconstruction, threads number:" << (int)n_threads <<std::endl; 

    for (uint64_t id = 0; id < n_threads; id++)
    {
        threads.push_back(std::thread(thread_reconstruct, id, n_threads));
    }

logger::log(logger::INFO)<< "before join" <<std::endl; 

    for (auto &t : threads)
    {
        t.join();
    }

logger::log(logger::INFO)<< "after join" <<std::endl; 

std::chrono::high_resolution_clock::time_point t5 = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t1).count();
logger::log(logger::INFO)<< "Time for bulk_reconstruct() with Network:"  << duration / (request->end_id() - request->begin_id())  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

        return  grpc::Status::OK;
    } */

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