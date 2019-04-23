#include "leath_client_runner.h"

#include <grpc/grpc.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

namespace mpc
{
LeathClientRunner::LeathClientRunner(const std::vector<std::string> &addresses, const std::string client_path, const int bits) : client_dir(client_path), current_step(1), already_setup(false), abort(false)
{
    for (auto &address : addresses)
    {
        std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
        stub_vector.push_back((leath::LeathRPC::NewStub(channel)));
    }

    number_of_servers = addresses.size();

    // client_.reset( new LeathClient(client_path, number_of_servers, 1024) );

    if (is_directory(client_path))
    {
        client_ = LeathClient::construct_from_directory(client_path, number_of_servers, bits);
        already_setup = true;
        logger::log(logger::INFO) << "Setup from dir, N =  " << client_->client_share.N.to_string() << std::endl;
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

std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();

    if (already_setup)
    {
        logger::log(logger::ERROR) << "Setup is already finished!" << std::endl;
        return;
    }
    leath_setup_message1_t out1;
    client_->leath_setup_peer1_step1(mem_t::from_string("setup_session"), out1);

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

        logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step2(): "
                                  << " begin..." << std::endl;

        leath_setup_message2_t in;
        ub::convert(in, mem_t::from_string(response.msg()));
        client_->leath_setup_peer1_step2(mem_t::from_string("setup_session"), id, in);

        logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step2(): "
                                  << " done." << std::endl;

        // send mac share
        logger::log(logger::INFO) << "Thread " << (int)id << " leath_setup_peer1_step3(): "
                                  << " begin..." << std::endl;

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

    // in the end, store client share !
    already_setup = true;
    client_->write_share();
std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for Setup with network:"  << duration  << " ms" <<std::endl;

} //setup


void LeathClientRunner::simple_setup()
{

std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();

    if (already_setup)
    {
        logger::log(logger::ERROR) << "Setup is already finished!" << std::endl;
        return;
    }
    leath_setup_message1_t out1;
    client_->leath_setup_peer1_step1(mem_t::from_string("setup_session"), out1);

    logger::log(logger::INFO) << "Before simple setup..." << std::endl;

    for(int id =0; id < number_of_servers; id++) {
        logger::log(logger::INFO) <<  "simple setup for server " << (int)id << " begins" << std::endl;

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

        logger::log(logger::INFO) <<  "simple setup for server " << (int)id << " leath_setup_peer1_step2(): "
                                  << " begin..." << std::endl;

        leath_setup_message2_t in;
        ub::convert(in, mem_t::from_string(response.msg()));
        client_->leath_setup_peer1_step2(mem_t::from_string("setup_session"), id, in);

        logger::log(logger::INFO) <<  "simple setup for server " << (int)id << " leath_setup_peer1_step2(): "
                                  << " done." << std::endl;

        // send mac share
        logger::log(logger::INFO) <<  "simple setup for server " << (int)id << " leath_setup_peer1_step3(): "
                                  << " begin..." << std::endl;

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

        logger::log(logger::INFO) << "simple setup for server " << (int)id << ", leath_setup_peer1_step3(): "
                                  << " done." << std::endl;
    }

    // in the end, store client share !
    already_setup = true;
    client_->write_share();

std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for simple Setup with network:"  << duration  << " ms" <<std::endl;

} //setup

error_t LeathClientRunner::share(const uint64_t val_id, const bn_t& val)
{
    error_t rv = 0;
    // logger::log(logger::INFO)<< "share begins ... "  <<std::endl;
std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();

    if (!already_setup)
    {
        logger::log(logger::ERROR) << "No setup!" << std::endl;
        return ub::error(E_NOT_READY);
    }

    std::vector<leath_maced_share_t> out_vector;
    client_->leath_share_peer1_step1(ub::mem_t::from_string("share_session"), val, out_vector);

    auto p2p_share = [this, &val_id, &out_vector](int id) {
        logger::log(logger::INFO) << "Thread " << (int)id << " begins" << std::endl;

        grpc::ClientContext context;
        leath::ShareRequestMessage request;
        google::protobuf::Empty response;
        grpc::Status status;

        request.set_value_id(val_id);
        request.set_value_share(ub::convert(out_vector[id].share).to_string());
        request.set_mac_share(ub::convert(out_vector[id].mac_share).to_string());
        status = stub_vector[id]->share(&context, request, &response);
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


std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
logger::log(logger::INFO)<< "Time for Share with Network:"  << duration  << " ms" <<std::endl;// printf("p_6144 decryption: %f ms \n", duration / (count));

    return 0;
} //share

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
        if (!status.ok())
        {
            logger::log(logger::ERROR) << "Reoncstruct for server: " << (int)id << " failed." << std::endl;
            return ub::error(E_UNAVAILABLE);
        }

        leath_maced_share_t in_share;

        
        in_share.share = bn_t::from_string(response.value_share().c_str());
        in_share.mac_share = bn_t::from_string(response.mac_share().c_str());
        logger::log(logger::INFO) << "Thread " << id << ": Reoncstruct received value_share size: " << in_share.share.to_bin().size() << std::endl;
        logger::log(logger::INFO) << "Thread " << id << ": Reoncstruct received mac_share size: " << in_share.mac_share.to_bin().size() << std::endl;
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



} // namespace mpc