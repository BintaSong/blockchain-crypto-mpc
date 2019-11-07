#include "yak_server.h"

namespace mpc
{
    YakServer::YakServer(const ecc_point_t _my_pk, const bn_t _my_sk, const std::string _my_addr, const std::string _peer_address) {
        my_addr = _my_addr;
        my_pk = _my_pk;
        my_sk = _my_sk;
        peer_addr = _peer_address;
    }

    error_t YakServer::yak_peer2_step1(const mem_t session_id, const yak_msg_t in, yak_msg_t &out) {
       
        error_t rv = 0; 

        ecurve_t curve = my_pk.get_curve();
        bn_t order = curve.order(); 
        ecc_generator_point_t G = curve.generator();
        

        if (0 != check_pk_match(in.pk, peer_addr) || !in.eph_zkp.v(curve, in.eph, session_id, 1))
        {
            logger::log(logger::ERROR) << "Check failed." << std::endl; 
            return ub::error(E_BADARG); 
        }

	    bn_t my_esk = bn_t::rand(order); 
        out.eph = G * my_esk;
        out.eph_zkp.p(curve, my_pk, session_id + mem_t::from_string(my_addr), 1, my_esk); 
        out.pk = my_pk; 
        
        ecc_point_t result = (in.pk + in.eph) * (my_sk + my_esk);
        mem_t key = kdf(result);

        return rv; 
    }
} //namespace mpc
