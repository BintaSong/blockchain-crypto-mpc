#include "leath_server_runner.h"


#include <stdio.h>
#include <csignal>
#include <unistd.h>

grpc::Server *server_ptr__ = NULL;

void exit_handler(int signal)
{
    std::cout << "INFO: " << "\nExiting ... " << std::endl;
    
    if (server_ptr__) {
        server_ptr__->Shutdown();
    }
};


int main(int argc, char** argv) {

    std::signal(SIGTERM, exit_handler);
    std::signal(SIGINT, exit_handler);
    std::signal(SIGQUIT, exit_handler);

    opterr = 0;
    int c;

    bool async_search = true;
    
    std::string server_address;
    uint8_t server_id;
    while ((c = getopt (argc, argv, "i:s:r")) != -1)
    switch (c)
    {
        case 'i':
            server_id = std::stoi( std::string(optarg));
            break;
        case 's':
           //TODO: 
            break;
        
        case 'r':
            //TODO: 
            break;
        
        case 'a':
            //TODO: 
            server_address = std::string(optarg);
            break;

        // case '?':
        //     if (optopt == 'i')
        //         fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        //     else if (isprint (optopt))
        //         fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        //     else
        //         fprintf (stderr,
        //                  "Unknown option character `\\x%x'.\n",
        //                  optopt);
        //     return 1;
        default:
            exit(-1);
    }

    mpc::run_leath_server();
    

    std::cout << "INFO:" << "Done." << std::endl;
    
    return 0;
}
