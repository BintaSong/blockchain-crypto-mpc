#include "leath_client_runner.h"

#include <grpc/grpc.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

namespace mpc
{
std::mutex LeathClientRunner::RS_mtx;

LeathClientRunner::LeathClientRunner(const std::vector<std::string> &addresses, const std::string client_path, const int bits) : client_dir(client_path), current_step(1), already_setup(false), abort(false)
{
    // addr_vector = addresses;

    for (int i = 0; i < addresses.size(); i++)
    {
        std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(addresses[i], grpc::InsecureChannelCredentials()));
        stub_vector.push_back(std::move(leath::LeathRPC::NewStub(channel)));
    }

    number_of_servers = (uint64_t) addresses.size();

    // client_.reset( new LeathClient(client_path, number_of_servers, 1024) );

    if (is_directory(client_path))
    {
        client_ = LeathClient::construct_from_directory(client_path, number_of_servers, bits);
        already_setup = true;
        logger::log(logger::INFO) << "Setup from dir, |N| =  " << client_->client_share.N.get_bin_size() << std::endl;
    }
    else if (exists(client_path))
    {
        throw std::runtime_error(client_path + ": not a directory");
    }
    else
    {
        // FIXME: the first time run only create directory, nothing else!
        if (!create_directory(client_path, (mode_t)0700))
        {
            throw std::runtime_error(client_path + ": unable to create directory");
        }
        client_ = LeathClient::init_in_directory(client_path, number_of_servers, bits);
        
    }
}

void LeathClientRunner::pre_setup()
{
    //TODO: 
    logger::log(logger::INFO) << "Pre setup begins ... " << std::endl;

    auto p2p_presetup = [this](int server_id){
        grpc::ClientContext context1;
        google::protobuf::Empty request;
        leath::preSetupMessage response;
        grpc::Status status;

        status = stub_vector[server_id]->pre_setup(&context1, request, &response);
        if (!status.ok())
        {
            logger::log(logger::ERROR) << "Setup for server " << (int)server_id << " failed." << std::endl;
            return;
        }

        leath_pre_setup_message1_t in;

        in.G = bn_t::from_string( response.g().c_str() );
        in.H = bn_t::from_string( response.h().c_str() );
        in.range_N = bn_t::from_string( response.n().c_str() );

        client_->leath_pre_setup_peer1_step1(mem_t::from_string("pre_setup_session"), server_id, in);
    };


    std::vector<std::thread> threads;
    for (int t = 0; t < number_of_servers; t++)
    {
        threads.push_back(std::thread(p2p_presetup, t));
    }
    for (auto &t : threads)
    {
        t.join();
    }
}

void LeathClientRunner::setup()
{
    logger::log(logger::INFO) << "Setup begins ... " << std::endl;


    if (already_setup)
    {
        logger::log(logger::ERROR) << "Setup is already finished!" << std::endl;
        return;
    }


std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

    client_->leath_setup_paillier_generation();

std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
double d2 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
logger::log(logger::INFO)<< "*TOTAL* Time for paillier key and parameters generation:"  << d2  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));



std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();

    leath_setup_message1_t out1;
    client_->leath_setup_peer1_step1(mem_t::from_string("setup_session"), out1);

std::chrono::high_resolution_clock::time_point t0 = std::chrono::high_resolution_clock::now();
double d0 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t0 - begin).count();
logger::log(logger::INFO) << "time for leath_setup_peer1_step1():"  << d0 << " us" <<std::endl;

    int8_t id = 0;
    auto p2p_setup = [this](int id, leath_setup_message1_t out) {
        // logger::log(logger::INFO) << "Thread " << (int)id << " begins" << std::endl;
        leath_setup_message1_t update_out = out;
        // update range proof for each server, FIXME: the bit size of DF commitment is fiexed to 2048
        
        RS_mtx.lock();
            crypto::paillier_t pail; pail.create_pub(update_out.N);
            update_out.zk_DF_Paillier_range.p(update_out.c_1, 2, update_out.N - 1, client_->client_share.G[id], client_->client_share.H[id], client_->client_share.range_N[id], pail, 2048, mem_t::from_string("setup_session"), 1, client_->client_share.x_1, client_->client_share.r_1);
            /*if(! update_out.zk_DF_Paillier_range.v(update_out.c_1, 2, out.N - 1, client_->client_share.G[id], client_->client_share.H[id], client_->client_share.range_N[id], out.N,  2048, mem_t::from_string("setup_session"), 1) )
            {
                logger::log(logger::INFO) << "**** verify failed ****" << std::endl;
            }
            */
        RS_mtx.unlock();

        grpc::ClientContext context1;
        leath::SetupMessage request, response;
        grpc::Status status;

        request.set_msg_id(1);
        request.set_msg(ub::convert(update_out).to_string());
        // request.set_msg();
    logger::log(logger::INFO) << "leath_setup_peer1_step1 message length:" << request.msg().size() << std::endl;

    std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

        status = stub_vector[id]->setup(&context1, request, &response);
        if (!status.ok())
        {
            logger::log(logger::ERROR) << "Setup for server " << (int)id << " failed." << std::endl;
            return;
        }

    std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
    double d21 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    logger::log(logger::INFO)<< "Thread " << id << ", time for leath_setup_peer1_step() RPC time:"  << d21 << " us" <<std::endl;


        if (response.msg_id() != 2)
        {
            logger::log(logger::ERROR) << "Received message not matching current step." << std::endl;
            return;
        }

        //logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step2(): "
         //                         << " begin..." << std::endl;

    std::chrono::high_resolution_clock::time_point t3 = std::chrono::high_resolution_clock::now();
        leath_setup_message2_t in;
        ub::convert(in, mem_t::from_string(response.msg()));
        client_->leath_setup_peer1_step2(mem_t::from_string("setup_session"), id, in);
    std::chrono::high_resolution_clock::time_point t4 = std::chrono::high_resolution_clock::now();
    double d43 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();
    logger::log(logger::INFO)<< "Thread " << id << ", time for leath_setup_peer1_step2():"  << d43 << " us" <<std::endl;


        leath_setup_message3_t out3;
        client_->leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), id, out3);

    std::chrono::high_resolution_clock::time_point t5 = std::chrono::high_resolution_clock::now();
    double d54 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t5 - t4).count();
    logger::log(logger::INFO)<< "Thread " << id << ", time for leath_setup_peer1_step3():"  << d54 << " us" <<std::endl;


        grpc::ClientContext context2;
        request.set_msg_id(3);
        request.set_msg(ub::convert(out3).to_string());
        status = stub_vector[id]->setup(&context2, request, &response);

    std::chrono::high_resolution_clock::time_point t6 = std::chrono::high_resolution_clock::now();
    double d65 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t6 - t5).count();
    logger::log(logger::INFO)<< "Thread " << id << ", time for leath_setup_peer1_step3() RPC time:"  << d65 << " us" <<std::endl;


        if (!status.ok())
        {
            logger::log(logger::ERROR) << "Setup for server " << id << " failed." << std::endl;
            return;
        }

        // logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step3(): " << " done." << std::endl;
    };

    std::vector<std::thread> threads;

    for (int t = 0; t < number_of_servers; t++)
    {
        threads.push_back(std::thread(p2p_setup, t, out1));
    }
    for (auto &t : threads)
    {
        t.join();
    }

std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();

    // in the end, store client share !
    already_setup = true;
    client_->write_share();

logger::log(logger::INFO)<< "Time for Setup with network:"  << duration  << " us" <<std::endl;

} //setup


void LeathClientRunner::simple_setup()
{
    if (already_setup)
    {
        logger::log(logger::ERROR) << "Setup is already finished!" << std::endl;
        return;
    }

std::chrono::high_resolution_clock::time_point t0 = std::chrono::high_resolution_clock::now();

    client_->leath_setup_paillier_generation();

std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
double d0 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
logger::log(logger::INFO)<< "Time for paillier key and parameters generation:"  << d0  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


    leath_setup_message1_t out1;
    client_->leath_setup_peer1_step1(mem_t::from_string("setup_session"), out1);

std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
double d1 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
logger::log(logger::INFO)<< "Time for leath_setup_peer1_step1():"  << d1  << " us" <<std::endl;

    for(int id = 0; id < number_of_servers; id++)
    { 
        // std::shared_ptr<grpc::Channel> channel0(grpc::CreateChannel(addresses[0], grpc::InsecureChannelCredentials()));
        // std::unique_ptr<leath::LeathRPC::Stub> stub_0= leath::LeathRPC::NewStub(channel0);
        std::chrono::high_resolution_clock::time_point t3_ = std::chrono::high_resolution_clock::now();
                grpc::ClientContext context1;
                leath::SetupMessage request, response;
                grpc::Status status;

        std::chrono::high_resolution_clock::time_point t3 = std::chrono::high_resolution_clock::now();
                
                leath_setup_message1_t out_1 = out1;
                out_1.update_range_proof(client_->client_share.G[id], client_->client_share.H[id], 2048, client_->client_share.range_N[id], client_->client_share.x_1, client_->client_share.r_1, mem_t::from_string("setup_session"));
                // crypto::paillier_t pail; pail.create_pub(out1.N);
                // out1.zk_DF_Paillier_range.p(out1.c_1, 2, out1.N - 1, client_->client_share.G[id], client_->client_share.H[id], client_->client_share.range_N[id], pail, 2048, mem_t::from_string("setup_session"), 1, client_->client_share.x_1, client_->client_share.r_1);
                /* 
                    if(! out_1.zk_DF_Paillier_range.v(out_1.c_1, 2, out_1.N - 1, client_->client_share.G[id], client_->client_share.H[id], client_->client_share.range_N[id], out_1.N,  2048, mem_t::from_string("setup_session"), 1) )
                    {
                        logger::log(logger::INFO) << "**** YOU ARE FUCKED ****" << std::endl;
                    }
                */
                request.set_msg_id(1);
                request.set_msg(ub::convert(out_1).to_string());

        std::chrono::high_resolution_clock::time_point t4 = std::chrono::high_resolution_clock::now();
        double d2 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();
        logger::log(logger::INFO)<< "Server " << id <<", time for setup message `leath_setup_message1_t` encoding: "  << d2  << " us" <<std::endl;

        time_t now = time(0); 
        logger::log(logger::INFO)<< "Current time:"  << now  << " s" <<std::endl;

                status = stub_vector[id]->setup(&context1, request, &response);
                //status = setup_rpc(id, request, &response);

        std::chrono::high_resolution_clock::time_point t5 = std::chrono::high_resolution_clock::now();
        double d3 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t5 - t4).count();
        logger::log(logger::INFO)<< "Server " << id <<",Time for setup message `leath_setup_message1_t` RPC: "  << d3  << " us" <<std::endl;

                if (!status.ok())
                {
                    logger::log(logger::ERROR) << "Setup for server " << (int)id << " failed." << std::endl;
                    return;
                }

                if (response.msg_id() != 2)
                {
                    logger::log(logger::ERROR) << "Received message not matching current step." << std::endl;
                    return;
                }

                // logger::log(logger::INFO) <<  "simple setup for server " << (int)id << " leath_setup_peer1_step2(): "
                //                           << " begin..." << std::endl;


                leath_setup_message2_t in;
                ub::convert(in, mem_t::from_string(response.msg()));

        std::chrono::high_resolution_clock::time_point t6 = std::chrono::high_resolution_clock::now();
        double d4 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t6 - t5).count();
        logger::log(logger::INFO)<< "Server " << id <<", time for setup message `leath_setup_message2_t` encoding: "  << d4  << " us" <<std::endl;

                client_->leath_setup_peer1_step2(mem_t::from_string("setup_session"), id, in);
        std::chrono::high_resolution_clock::time_point t7 = std::chrono::high_resolution_clock::now();
        double d5 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t7 - t6).count();
        logger::log(logger::INFO)<< "Server " << id <<", time for `leath_setup_peer1_step2`: "  << d5  << " us" <<std::endl;

                // logger::log(logger::INFO) <<  "simple setup for server " << (int)id << " leath_setup_peer1_step2(): "
                //                          << " done." << std::endl;

                // send mac share
                //logger::log(logger::INFO) <<  "simple setup for server " << (int)id << " leath_setup_peer1_step3(): "
                //                          << " begin..." << std::endl;
                leath_setup_message3_t out3;
                client_->leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), id, out3);

        std::chrono::high_resolution_clock::time_point t8 = std::chrono::high_resolution_clock::now();
        double d6 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t8 - t7).count();
        logger::log(logger::INFO)<< "Server " << id <<", time for `leath_setup_peer1_step3`: "  << d6  << " us" <<std::endl;

                grpc::ClientContext context2;
                request.set_msg_id(3);
                request.set_msg(ub::convert(out3).to_string());

        std::chrono::high_resolution_clock::time_point t9 = std::chrono::high_resolution_clock::now();
        double d7 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t9 - t8).count();
        logger::log(logger::INFO)<< "Server " << id <<", time for `leath_setup_message3_t` encoding: "  << d7  << " us" <<std::endl;


                status = stub_vector[id]->setup(&context2, request, &response);
                // status = setup_rpc(id, request, &response);

        std::chrono::high_resolution_clock::time_point t10 = std::chrono::high_resolution_clock::now();
        double d8 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t10 - t9).count();
        logger::log(logger::INFO)<< "Server " << id <<", time for `leath_setup_message3_t` RPC: "  << d8  << " us" <<std::endl;

                if (!status.ok())
                {
                    logger::log(logger::ERROR) << "Setup for server " << id << " failed." << std::endl;
                    return;
                }

                logger::log(logger::INFO) << "Simple setup for server " << (int)id << ", Done. \n" << std::endl;
    } //end of for

    std::chrono::high_resolution_clock::time_point t11 = std::chrono::high_resolution_clock::now();

    // in the end, store client share !
    already_setup = true;
    client_->write_share();

    std::chrono::high_resolution_clock::time_point t12 = std::chrono::high_resolution_clock::now();
    double d9 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t12 - t11).count();
    logger::log(logger::INFO)<< "Time for write_share():"  << d9  << " us" <<std::endl;

    double d10 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t12 - t1).count();
    logger::log(logger::INFO)<< "TOTAL TIME FOR SIMPLE SETUP:"  << d10  << " us" <<std::endl;
} //setup

error_t LeathClientRunner::share(const uint64_t val_id, const bn_t& val)
{
    error_t rv = 0;
    // logger::log(logger::INFO)<< "share begins ... "  <<std::endl;
// std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();

    if (!already_setup)
    {
        logger::log(logger::ERROR) << "No setup!" << std::endl;
        return ub::error(E_NOT_READY);
    }

    std::vector<leath_maced_share_t> out_vector;
    client_->leath_share_peer1_step1(ub::mem_t::from_string("share_session"), val, out_vector);

    auto p2p_share = [this, &val_id, &out_vector](int id) {
        // logger::log(logger::INFO) << "Share Thread " << (int)id << " begins" << std::endl;

        grpc::ClientContext context;
        leath::ShareRequestMessage request;
        google::protobuf::Empty response;
        grpc::Status status;

        request.set_value_id(val_id);
        request.set_value_share(ub::convert(out_vector[id].share).to_string());
        request.set_mac_share(ub::convert(out_vector[id].mac_share).to_string());
        status = stub_vector[id]->share(&context, request, &response);
        // status = share_rpc(id, request);
        if (!status.ok())
        {
            logger::log(logger::ERROR) << "Share for server " << id << " failed." << std::endl;
            return ub::error(E_UNAVAILABLE);
        }
    };

    std::vector<std::thread> threads;

    for (int t = 0; t < number_of_servers; t++)
    {
        threads.push_back(std::thread(p2p_share, t));
    }
    for (auto &t : threads)
    {
        t.join();
    }


//std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
//double duration = (double)std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
//logger::log(logger::INFO)<< "Time for Share with Network:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

    return 0;
} // share

// error_t LeathClientRunner::batch_share_benchmark(int counter) {

//     if (!already_setup)
//     {
//         logger::log(logger::ERROR) << "No setup!" << std::endl;
//         return ub::error(E_NOT_READY);
//     }

//     grpc::ClientContext context;
//     google::protobuf::Empty response;
// // init writer for each server
//     std::vector<std::unique_ptr<grpc::ClientWriter<leath::ShareRequestMessage>>> writer_vector;
//     for (int i = 0; i < stub_vector.size(); i++) {
//         std::unique_ptr<grpc::ClientWriter<leath::ShareRequestMessage>> writer = stub_vector[i]->batch_share(&context, &response);
//         writer_vector.push_back(std::move(writer));
//     }

// std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();



//     std::vector<leath_maced_share_t> out_vector;
//     client_->leath_share_peer1_step1(ub::mem_t::from_string("share_session"), val, out_vector);

//     auto p2p_share = [this, &val_id, &out_vector](int id) {
//         logger::log(logger::INFO) << "Thread " << (int)id << " begins" << std::endl;

//         grpc::ClientContext context;
//         leath::ShareRequestMessage request;
//         google::protobuf::Empty response;
//         grpc::Status status;

//         request.set_value_id(val_id);
//         request.set_value_share(ub::convert(out_vector[id].share).to_string());
//         request.set_mac_share(ub::convert(out_vector[id].mac_share).to_string());
//         status = stub_vector[id]->share(&context, request, &response);
//         // status = share_rpc(id, request);
//         if (!status.ok())
//         {
//             logger::log(logger::ERROR) << "Share for server " << id << " failed." << std::endl;
//             return ub::error(E_UNAVAILABLE);
//         }
//     };

//     std::vector<std::thread> threads;

//     for (int t = 0; t < number_of_servers; t++)
//     {
//         threads.push_back(std::thread(p2p_share, t));
//     }
//     for (auto &t : threads)
//     {
//         t.join();
//     }


// std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
// double duration = (double)std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
// logger::log(logger::INFO)<< "Time for Share with Network:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

//     return 0;
// }

error_t LeathClientRunner::share_benchmark(uint64_t begin, uint64_t end) {
    bn_t p = client_->client_share.paillier.get_p();

    // std::vector<leath_share_writers_t> writer_vector;

    if (begin >= end)
    {
        return 0;
    }

    leath_share_writers_t *writer_array = new leath_share_writers_t[number_of_servers];

    for(uint64_t i = 0; i < number_of_servers; i++) {
        writer_array[i].context.reset(new grpc::ClientContext());
        writer_array[i].response.reset(new leath::batchShareReply());
        writer_array[i].writer_ = stub_vector[i]->batch_share(writer_array[i].context.get(), writer_array[i].response.get());
    }

std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

    std::atomic_uint share_size(0);
    std::mutex mtx;
    auto share_callback = [&writer_array](const uint64_t server_id, const leath_maced_share_with_VID_t out_share){
        leath::ShareRequestMessage request;

        request.set_value_id(out_share.val_id);
        request.set_value_share(ub::convert(out_share.maced_share.share).to_string());
        request.set_mac_share(ub::convert(out_share.maced_share.mac_share).to_string());

        writer_array[server_id].mtx.lock();
        if(! writer_array[server_id].writer_->Write(request))
        {
            logger::log(logger::ERROR) << "share session: broken stream." << std::endl;
        }
        writer_array[server_id].mtx.unlock();
    };

     auto share_job = [this, &p, &share_size, &share_callback](const uint64_t begin_vid, const uint64_t end_vid, const uint64_t step){
        for(uint64_t vid = begin_vid; vid < end_vid; vid += step){
            bn_t raw_data = bn_t::rand(p);
            client_->leath_share_peer1_step1_callback(ub::mem_t::from_string("share_session"), vid, raw_data, share_callback);
            share_size++;
        }
    }; 

//-------------------------single thread for share----------------------------
    for(uint64_t vid = begin; vid < end; vid++) {
        bn_t raw_data =  bn_t::rand(p);
        client_->leath_share_peer1_step1_callback(ub::mem_t::from_string("share_session"), vid, raw_data, share_callback);
    }
     for(uint64_t server_id = 0; server_id < number_of_servers; server_id++) {

        writer_array[server_id].writer_->WritesDone();
        grpc::Status status = writer_array[server_id].writer_->Finish();
            
        if (!status.ok()) {
            logger::log(logger::ERROR) << "Status not OK for server "<< server_id <<", Status: " << status.error_message() << std::endl;
        }
     }

//--------------------multi threads option for share------------------

/*
    std::vector<std::thread> share_threads;

    unsigned n_threads = 2;
    // unsigned n_threads = number > 0 ? number : (std::thread::hardware_concurrency()  -1);
    
    for (uint8_t t = 0; t < n_threads; t++) {
        share_threads.push_back(std::thread(share_job, t, end, n_threads));
    }     
    for (auto& t : share_threads) {
        t.join();
    }

std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
logger::log(logger::INFO)<< "threads number: "<< n_threads <<", shared size: "<< share_size <<", time for share_benchmark() with Network:"  << duration /(share_size)  << " ms per share" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));
*/

std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
logger::log(logger::INFO)<<"SINGLE THREAD SHARE_BENCHMARK: Shared size: "<< (end - begin) <<", time for share_benchmark() with Network:"  << duration << " us in total" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


    delete [] writer_array;

    return 0;
}


/* error_t LeathClientRunner::share_benchmark(uint64_t begin, uint64_t end) {
    bn_t p = client_->client_share.paillier.get_p();

    std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

    for (uint64_t i = begin; i < end; i++) {
        share(i, bn_t(i));
    }
    std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
    double duration = (double)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    logger::log(logger::INFO)<< "Time for share_benchmark() with Network:"  << duration /(end - begin)  << " ms per share" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

    return 0;
}
 */

error_t LeathClientRunner::reconstruct(const uint64_t val_id, bn_t& raw_data)
{
std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();

    error_t rv = 0;
    if (!already_setup)
    {
        logger::log(logger::ERROR) << "No setup!" << std::endl;
        return ub::error(E_NOT_READY);
    }

    std::vector<leath_maced_share_t> cipher_in;
    std::mutex cipher_in_mutex;
    auto p2p_reconstruct = [this, &val_id, &cipher_in, &cipher_in_mutex](int id) {
        logger::log(logger::INFO) << "Thread " << (int)id << " begins" << std::endl;

        grpc::ClientContext context;
        leath::ReconstructRequestMessage request;
        leath::ReconstructReply response;
        grpc::Status status;

        request.set_value_id(val_id);

        status = stub_vector[id]->reconstruct(&context, request, &response);
        // status = reconstruct_rpc(id, request, &response);
        if (!status.ok())
        {
            logger::log(logger::ERROR) << "Reoncstruct for server: " << (int)id << " failed." << std::endl;
            return ub::error(E_UNAVAILABLE);
        }

        leath_maced_share_t in_share;

        in_share.share = bn_t::from_string(response.value_share().c_str());
        in_share.mac_share = bn_t::from_string(response.mac_share().c_str());

        cipher_in_mutex.lock();
        cipher_in.push_back(in_share);
        cipher_in_mutex.unlock();
    };

    std::vector<std::thread> threads;

    for (int t = 0; t < number_of_servers; t++)
    {
        threads.push_back(std::thread(p2p_reconstruct, t));
    }
    for (auto &t : threads)
    {
        t.join();
    }
    // reconstruct data;
    if (cipher_in.size() != number_of_servers) {
        logger::log(logger::ERROR) << "Some shares are lost!" << std::endl;
        exit(-1);
    }
    rv = client_->leath_reconstruct_peer1_step1(mem_t::from_string("reconstruction_session"), val_id, cipher_in, raw_data);

    assert(rv == 0);
    if (rv != 0) {
        logger::log(logger::ERROR) << "LeathClientRunner::reconstruct(): failed!" << raw_data.to_string() << std::endl;
        return ub::error(E_AUTH);
    }

std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for reconstruct with network:"  << duration  << " us" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));
    return 0;
} //reconstruction



//------------------------bulk_reconstruct--------------------------

error_t LeathClientRunner::bulk_reconstruct(const uint64_t begin, const uint64_t end) {

    error_t rv = 0;
    if (!already_setup)
    {
        logger::log(logger::ERROR) << "No setup!" << std::endl;
        return ub::error(E_NOT_READY);
    }

    if (begin >= end)
    {
        return 0;
    }

    struct data_with_counter_t {
        leath_maced_share_t in_share{1, 0};
        std::atomic_uint received_share_counter{0};
        std::mutex mtx;
    };

    uint64_t range = end - begin;

    data_with_counter_t *data_ = new data_with_counter_t[end - begin];
    // bn_t *raw_data_array = new bn_t[end - begin];


std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

    std::atomic_uint reconstruct_size(0);
    std::atomic<std::int32_t> total_decryption_time(0);
    std::atomic<std::int32_t> total_decoding_time(0);

    uint pool_size = 1;
    ThreadPool reconstruct_pool(pool_size);
    ThreadPool decoding_pool(1);

    auto post_back = [this] (bn_t raw_data) {
        //TODO: 
    };


    auto reconstruct_job = [this, &reconstruct_size, &total_decryption_time, &post_back](const uint64_t vid, const leath_maced_share_t maced_share) {
        error_t rv = 0;

            std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

        bn_t e_data = client_->client_share.paillier.decrypt(maced_share.share);

        rv = client_->check_data(e_data, maced_share.mac_share);
        if (rv != 0)
        {
            logger::log(logger::ERROR) << "reconstruct_data_mac(): MAC Check Failed!" << std::endl;
            return rv;
        }

        MODULO(client_->client_share.p) e_data = e_data - 0;

            std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
            int64_t d = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
            total_decryption_time += d;

        post_back(e_data);

        reconstruct_size++;
        if(reconstruct_size % 10000 == 0)  logger::log(logger::INFO) << "Just reconstruct " << reconstruct_size << " shares..." << std::endl;
    };

    auto decoding_job = [this, &data_, &total_decoding_time, &reconstruct_pool, &reconstruct_job](const leath::ReconstructReply reply) {

        std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
 
        uint64_t vid = reply.value_id();

        data_[vid].mtx.lock();       
        data_[vid].in_share.share *= bn_t::from_string(reply.value_share().c_str());
        data_[vid].in_share.mac_share += bn_t::from_string(reply.mac_share().c_str());
        data_[vid].mtx.unlock();
        
            std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
            int64_t d = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
            total_decoding_time += d;

        data_[vid].received_share_counter++;
        
        if (data_[vid].received_share_counter == number_of_servers) {
            reconstruct_pool.enqueue(reconstruct_job, vid, data_[vid].in_share);
        } 
    };

    auto p2p_reconstruct = [this, &begin, &end, &decoding_pool, &decoding_job](int server_id) {
        logger::log(logger::INFO) << "Reconstruction Thread " << (int)server_id << " begins" << std::endl;

        grpc::ClientContext context;
        leath::ReconstructRangeMessage request;
        leath::ReconstructReply reply;

        request.set_begin_id(begin);
        request.set_end_id(end);

        std::unique_ptr<grpc::ClientReaderInterface<leath::ReconstructReply>> reader(stub_vector[server_id]->bulk_reconstruct(&context, request));

        while (reader->Read(&reply)) {

            decoding_pool.enqueue(decoding_job, reply);

        }

        grpc::Status status = reader->Finish();

        if (status.ok()) {
            logger::log(logger::TRACE) << "Reconstruct RPC succee." << std::endl;
        } else {
            logger::log(logger::ERROR) << "Reconstruct RPC failed:" << std::endl;
            logger::log(logger::ERROR) << status.error_message() << std::endl;
        }
    };

    std::vector<std::thread> threads;

    for (int t = 0; t < number_of_servers; t++)
    {
        threads.push_back(std::thread(p2p_reconstruct, t));
    }
    for (auto &t : threads)
    {
        t.join();
    }

    decoding_pool.join();
    reconstruct_pool.join();

logger::log(logger::INFO)<< "benchmark size: " << range <<" ,total_decryption_time:"  << (double)total_decryption_time << " us" <<std::endl;

logger::log(logger::INFO)<< "benchmark size: " << range <<" ,total_decoding_time:"  << (double)total_decoding_time << " us" <<std::endl;


std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
double duration = (double) std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

logger::log(logger::INFO)<<" total reconstruction time:"  << (double) duration << " us" <<std::endl;

logger::log(logger::INFO)<< "reconstruct_pool size: "<< pool_size << ", Reconstructed " << reconstruct_size <<" data, time for reconstruct with network:"  << duration << " us in total" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));
    
    delete [] data_;
    // delete [] raw_data_array;

    return 0;
}


/* void LeathClientRunner::test_rpc() {
    grpc::ClientContext context1;
    grpc::ClientContext context2;
    grpc::ClientContext context3;
    grpc::ClientContext context4, context5, context6, context7, context8, context9;

    leath::ShareRequestMessage request;
    google::protobuf::Empty response;    
    grpc::Status status;

std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

    stub_vector[0]->share(&context1, request, &response);

std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
double d1 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
logger::log(logger::INFO)<< "Time for stub 0:"  << d1  << " us" <<std::endl;

     stub_vector[1]->share(&context2, request, &response);
std::chrono::high_resolution_clock::time_point t3 = std::chrono::high_resolution_clock::now();
double d2 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count();
logger::log(logger::INFO)<< "Time for stub 1:"  << d2  << " us" <<std::endl;

     stub_vector[0]->share(&context3, request, &response);

std::chrono::high_resolution_clock::time_point t4 = std::chrono::high_resolution_clock::now();
double d3 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();
logger::log(logger::INFO)<< "Time for stub 0:"  << d3  << " us" <<std::endl;

    stub_vector[1]->share(&context4, request, &response);
std::chrono::high_resolution_clock::time_point t5 = std::chrono::high_resolution_clock::now();
double d4 = (double)std::chrono::duration_cast<std::chrono::microseconds>(t5 - t4).count();
logger::log(logger::INFO)<< "Time for stub 1:"  << d4  << " us" <<std::endl;

    for(int i = 0; i < 10000; i++) {
        grpc::ClientContext context9, context10;
        logger::log(logger::INFO)<< "i = "  << i  <<std::endl;
        stub_vector[0]->share(&context9, request, &response);
        stub_vector[1]->share(&context10, request, &response);
    }
   

}
grpc::Status LeathClientRunner::setup_rpc(const int id, const leath::SetupMessage& request, leath::SetupMessage *response) {
    std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(addr_vector[id], grpc::InsecureChannelCredentials()));
    std::unique_ptr<leath::LeathRPC::Stub> stub = leath::LeathRPC::NewStub(channel);

    grpc::ClientContext context;
    grpc::Status status;

    status = stub->setup(&context, request, response);
    
    return status;
}
grpc::Status LeathClientRunner::share_rpc(const int id, const leath::ShareRequestMessage& request) {
    
    std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(addr_vector[id], grpc::InsecureChannelCredentials()));
    std::unique_ptr<leath::LeathRPC::Stub> stub = leath::LeathRPC::NewStub(channel);

    grpc::ClientContext context;
    google::protobuf::Empty response;
    grpc::Status status;

    status = stub->share(&context, request, &response);

    return status;
}
grpc::Status LeathClientRunner::reconstruct_rpc(const int id, const leath::ReconstructRequestMessage& request, leath::ReconstructReply *response) {

    std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(addr_vector[id], grpc::InsecureChannelCredentials()));
    std::unique_ptr<leath::LeathRPC::Stub> stub = leath::LeathRPC::NewStub(channel);

    grpc::ClientContext context;
    grpc::Status status;
    
    status = stub->reconstruct(&context, request, response);

    return status;
} */

} // namespace mpc