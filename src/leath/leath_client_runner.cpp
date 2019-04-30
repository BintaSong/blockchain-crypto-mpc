#include "leath_client_runner.h"

#include <grpc/grpc.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

namespace mpc
{
LeathClientRunner::LeathClientRunner(const std::vector<std::string> &addresses, const std::string client_path, const int bits) : client_dir(client_path), current_step(1), already_setup(false), abort(false)
{
    // addr_vector = addresses;

    for (int i = 0; i < addresses.size(); i++)
    {
        std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(addresses[i], grpc::InsecureChannelCredentials()));
        stub_vector.push_back(std::move(leath::LeathRPC::NewStub(channel)));
    }

    number_of_servers = addresses.size();

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
double d2 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
logger::log(logger::INFO)<< "Time for paillier key and parameters generation:"  << d2  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


    leath_setup_message1_t out1;
    client_->leath_setup_peer1_step1(mem_t::from_string("setup_session"), out1);

std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();


    // logger::log(logger::INFO) << "Before thread" << std::endl;

    int8_t id = 0;
    auto p2p_setup = [this, &out1](int id) {
        // logger::log(logger::INFO) << "Thread " << (int)id << " begins" << std::endl;

        grpc::ClientContext context1;
        leath::SetupMessage request, response;
        grpc::Status status;

        request.set_msg_id(1);
        request.set_msg(ub::convert(out1).to_string());
        // request.set_msg();
        logger::log(logger::INFO) << "leath_setup_peer1_step1 message length:" << request.msg().size() << std::endl;
        status = stub_vector[id]->setup(&context1, request, &response);
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

        //logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step2(): "
         //                         << " begin..." << std::endl;

        leath_setup_message2_t in;
        ub::convert(in, mem_t::from_string(response.msg()));
        client_->leath_setup_peer1_step2(mem_t::from_string("setup_session"), id, in);

        //logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step2(): "
         //                         << " done." << std::endl;

        // send mac share
        //logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step3(): "
        //                          << " begin..." << std::endl;

        leath_setup_message3_t out3;
        client_->leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), id, out3);

        grpc::ClientContext context2;
        request.set_msg_id(3);
        request.set_msg(ub::convert(out3).to_string());
        status = stub_vector[id]->setup(&context2, request, &response);
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
        threads.push_back(std::thread(p2p_setup, t));
    }
    for (auto &t : threads)
    {
        t.join();
    }

std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();

    // in the end, store client share !
    already_setup = true;
    client_->write_share();

logger::log(logger::INFO)<< "Time for Setup with network:"  << duration  << " ms" <<std::endl;

} //setup


void LeathClientRunner::parallel_setup()
{
    logger::log(logger::INFO) << "parallel_setup begins ... " << std::endl;


    if (already_setup)
    {
        logger::log(logger::ERROR) << "Setup is already finished!" << std::endl;
        return;
    }
    leath_setup_message1_t out1;
    client_->leath_setup_peer1_step1(mem_t::from_string("setup_session"), out1);

std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();


    logger::log(logger::INFO) << "Before thread" << std::endl;

    int8_t id = 0;
    auto p2p_setup = [this, &out1](int id) {
        logger::log(logger::INFO) << "Thread " << (int)id << " begins" << std::endl;

        grpc::ClientContext context1;
        leath::SetupMessage request, response;
        grpc::Status status;

        request.set_msg_id(1);
        request.set_msg(ub::convert(out1).to_string());
        status = stub_vector[id]->setup(&context1, request, &response);
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

        //logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step2(): "
         //                         << " begin..." << std::endl;

        leath_setup_message2_t in;
        ub::convert(in, mem_t::from_string(response.msg()));
        client_->leath_setup_peer1_step2(mem_t::from_string("setup_session"), id, in);

        //logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step2(): "
         //                         << " done." << std::endl;

        // send mac share
        //logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step3(): "
        //                          << " begin..." << std::endl;

        leath_setup_message3_t out3;
        client_->leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), id, out3);

        grpc::ClientContext context2;
        request.set_msg_id(3);
        request.set_msg(ub::convert(out3).to_string());
        status = stub_vector[id]->setup(&context2, request, &response);
        if (!status.ok())
        {
            logger::log(logger::ERROR) << "Setup for server " << id << " failed." << std::endl;
            return;
        }

        logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step3(): "
                                  << " done." << std::endl;
    };

    std::vector<std::thread> threads;

    for (int t = 0; t < number_of_servers; t++)
    {
        threads.push_back(std::thread(p2p_setup, t));
    }
    for (auto &t : threads)
    {
        t.join();
    }

std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();

    // in the end, store client share !
    already_setup = true;
    client_->write_share();

logger::log(logger::INFO)<< "Time for Setup with network:"  << duration  << " ms" <<std::endl;

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
double d0 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
logger::log(logger::INFO)<< "Time for paillier key and parameters generation:"  << d0  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));


    leath_setup_message1_t out1;
    client_->leath_setup_peer1_step1(mem_t::from_string("setup_session"), out1);

std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
double d1 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
logger::log(logger::INFO)<< "Time for leath_setup_peer1_step1():"  << d1  << " ms" <<std::endl;

    // logger::log(logger::INFO) << "Before simple setup..." << std::endl;

    // std::unique_ptr<leath::LeathRPC::Stub>;
    // std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
    // stub_vector.push_back(leath::LeathRPC::NewStub(channel));
    // std::string addresses[2] = {"0.0.0.0:7000", "0.0.0.0:7001"};


    for(int id =0; id < number_of_servers; id++) 
    { 
// std::shared_ptr<grpc::Channel> channel0(grpc::CreateChannel(addresses[0], grpc::InsecureChannelCredentials()));
// std::unique_ptr<leath::LeathRPC::Stub> stub_0= leath::LeathRPC::NewStub(channel0);

        

std::chrono::high_resolution_clock::time_point t3_ = std::chrono::high_resolution_clock::now();
        grpc::ClientContext context1;
        leath::SetupMessage request, response;
        grpc::Status status;

std::chrono::high_resolution_clock::time_point t3 = std::chrono::high_resolution_clock::now();

        request.set_msg_id(1);
        // request.set_msg(ub::convert(out1).to_string());
        request.set_msg(ub::convert(out1).to_string());

std::chrono::high_resolution_clock::time_point t4 = std::chrono::high_resolution_clock::now();
double d2 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count();
logger::log(logger::INFO)<< "Time for setup message `leath_setup_message1_t` encoding:"  << d2  << " ms" <<std::endl;

time_t now = time(0); 
logger::log(logger::INFO)<< "Current time:"  << now  << " s" <<std::endl;

        status = stub_vector[id]->setup(&context1, request, &response);
        //status = setup_rpc(id, request, &response);

std::chrono::high_resolution_clock::time_point t5 = std::chrono::high_resolution_clock::now();
double d3 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t4).count();
logger::log(logger::INFO)<< "Time for setup message `leath_setup_message1_t` rpc:"  << d3  << " ms" <<std::endl;

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
double d4 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t6 - t5).count();
logger::log(logger::INFO)<< "Time for setup message `leath_setup_message2_t` encoding:"  << d4  << " ms" <<std::endl;

        client_->leath_setup_peer1_step2(mem_t::from_string("setup_session"), id, in);
std::chrono::high_resolution_clock::time_point t7 = std::chrono::high_resolution_clock::now();
double d5 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t7 - t6).count();
logger::log(logger::INFO)<< "Time for `leath_setup_peer1_step2`:"  << d5  << " ms" <<std::endl;

        // logger::log(logger::INFO) <<  "simple setup for server " << (int)id << " leath_setup_peer1_step2(): "
        //                          << " done." << std::endl;

        // send mac share
        //logger::log(logger::INFO) <<  "simple setup for server " << (int)id << " leath_setup_peer1_step3(): "
        //                          << " begin..." << std::endl;
        leath_setup_message3_t out3;
        client_->leath_setup_peer1_step3(ub::mem_t::from_string("setup_session"), id, out3);

std::chrono::high_resolution_clock::time_point t8 = std::chrono::high_resolution_clock::now();
double d6 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t8 - t7).count();
logger::log(logger::INFO)<< "Time for `leath_setup_peer1_step3`:"  << d6  << " ms" <<std::endl;

        grpc::ClientContext context2;
        request.set_msg_id(3);
        request.set_msg(ub::convert(out3).to_string());

std::chrono::high_resolution_clock::time_point t9 = std::chrono::high_resolution_clock::now();
double d7 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t9 - t8).count();
logger::log(logger::INFO)<< "Time for `leath_setup_message2_t` encoding:"  << d7  << " ms" <<std::endl;


        status = stub_vector[id]->setup(&context2, request, &response);
        // status = setup_rpc(id, request, &response);

std::chrono::high_resolution_clock::time_point t10 = std::chrono::high_resolution_clock::now();
double d8 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t10 - t9).count();
logger::log(logger::INFO)<< "Time for `leath_setup_message2_t` rpc:"  << d8  << " ms" <<std::endl;

        if (!status.ok())
        {
            logger::log(logger::ERROR) << "Setup for server " << id << " failed." << std::endl;
            return;
        }

        logger::log(logger::INFO) << "simple setup for server " << (int)id << ", leath_setup_peer1_step3(): "
                                  << " done. \n\n\n\n" << std::endl;
       // stub_vector[id]->
    } //end of for

std::chrono::high_resolution_clock::time_point t11 = std::chrono::high_resolution_clock::now();

    // in the end, store client share !
    already_setup = true;
    client_->write_share();

std::chrono::high_resolution_clock::time_point t12 = std::chrono::high_resolution_clock::now();
double d9 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t11 - t12).count();
logger::log(logger::INFO)<< "Time for write_share():"  << d9  << " ms" <<std::endl;

double d10 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t12 - t1).count();
logger::log(logger::INFO)<< "TOTAL TIME FOR SETUP:"  << d10  << " ms" <<std::endl;


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
//double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
//logger::log(logger::INFO)<< "Time for Share with Network:"  << duration  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

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
// double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
// logger::log(logger::INFO)<< "Time for Share with Network:"  << duration  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

//     return 0;
// }

error_t LeathClientRunner::share_benchmark(uint64_t begin, uint64_t end) {
    bn_t p = client_->client_share.paillier.get_p();

    std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

    for (uint64_t i = begin; i < end; i++) {
        share(i, bn_t(i));
    }
    std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
    double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    logger::log(logger::INFO)<< "Time for share_benchmark() with Network:"  << duration /(end - begin)  << " ms per share" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

    return 0;
}

error_t LeathClientRunner::reconstruct_benchmark(int counter) {
    // // bn_t p = client_->client_share.paillier.get_p();
    // // bn_t raw_data;
    // bn_t shares[counter][number_of_servers];
    // bool finished[counter];
    // memset(finished, 0, counter);
    
    // TODO: 

    return 0;
}

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
       // logger::log(logger::INFO) << "Thread " << id << ": Reoncstruct received value_share size: " << in_share.share.to_bin().size() << std::endl;
       // logger::log(logger::INFO) << "Thread " << id << ": Reoncstruct received mac_share size: " << in_share.mac_share.to_bin().size() << std::endl;
        // ub::convert(share.share, mem_t::from_string(response.value_share()));
        // ub::convert(share.mac_share, mem_t::from_string(response.mac_share()));

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
    // raw_data.to_bin().data();
    assert(rv == 0);
    if (rv != 0) {
        logger::log(logger::ERROR) << "LeathClientRunner::reconstruct(): failed!" << raw_data.to_string() << std::endl;
        return ub::error(E_AUTH);
    }

std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for reconstruct with network:"  << duration  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));
    return 0;
} //reconstruction

error_t LeathClientRunner::bulk_reconstruct(const uint64_t begin, const uint64_t end) {

    grpc::ClientContext context;
    leath::ReconstructRangeMessage request;
    leath::ReconstructReply response;
    grpc::Status status; 

std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();

    error_t rv = 0;
    if (!already_setup)
    {
        logger::log(logger::ERROR) << "No setup!" << std::endl;
        return ub::error(E_NOT_READY);
    }

    // std::vector<leath_maced_share_t> shares = new [number_of_servers];

    auto p2p_reconstruct = [this, &begin, &end](int id) {
        logger::log(logger::INFO) << "Thread " << (int)id << " begins" << std::endl;

        grpc::ClientContext context;
        leath::ReconstructRangeMessage request;
        leath::ReconstructReply reply;

        request.set_begin_id(begin);
        request.set_end_id(end);

        std::unique_ptr<grpc::ClientReaderInterface<leath::ReconstructReply>> reader(stub_vector[id]->bulk_reconstruct(&context, request));

        while (reader->Read(&reply)) {
            if(reply.value_id() % 499 == 0) logger::log(logger::INFO)<< reply.value_id() <<std::endl;
        }
        grpc::Status status = reader->Finish();

        if (status.ok()) {
            logger::log(logger::TRACE) << "Reconstruct RPC succeeded." << std::endl;
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

std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
double duration = (double) std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
logger::log(logger::INFO)<< "Time for reconstruct with network:"  << duration / (end - begin) << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));
    
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
double d1 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
logger::log(logger::INFO)<< "Time for stub 0:"  << d1  << " ms" <<std::endl;

     stub_vector[1]->share(&context2, request, &response);
std::chrono::high_resolution_clock::time_point t3 = std::chrono::high_resolution_clock::now();
double d2 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();
logger::log(logger::INFO)<< "Time for stub 1:"  << d2  << " ms" <<std::endl;

     stub_vector[0]->share(&context3, request, &response);

std::chrono::high_resolution_clock::time_point t4 = std::chrono::high_resolution_clock::now();
double d3 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count();
logger::log(logger::INFO)<< "Time for stub 0:"  << d3  << " ms" <<std::endl;

    stub_vector[1]->share(&context4, request, &response);
std::chrono::high_resolution_clock::time_point t5 = std::chrono::high_resolution_clock::now();
double d4 = (double)std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t4).count();
logger::log(logger::INFO)<< "Time for stub 1:"  << d4  << " ms" <<std::endl;

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