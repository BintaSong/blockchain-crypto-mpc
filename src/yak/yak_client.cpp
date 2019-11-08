#include "yak_client.h"

namespace mpc
{
    YakClient::YakClient(const std::string _my_pk_hex, const std::string _my_sk_hex, const std::string _my_addr, const std::string _peer_address) {
        my_addr = _my_addr;
        peer_addr = _peer_address;
        my_pk = hex_to_point(_my_pk_hex);
        my_sk = bn_t::from_hex(_my_sk_hex.c_str());
    }

    error_t YakClient::yak_peer1_step1(const mem_t session_id, yak_msg_t &out) {
       
        error_t rv = 0;

        ecurve_t curve = ecurve_t::find(NID_secp256k1);
        ecc_generator_point_t G = curve.generator();
        const bn_t& order = curve.order();
           
	    bn_t _esk = bn_t::rand(order);
        my_esk = _esk;
        out.eph = G * _esk;
        out.eph_zkp.p(curve, out.eph, session_id + mem_t::from_string(my_addr), 1, _esk);
        out.pk = my_pk;
        logger::log(logger::INFO) << "in  yak_peer1_step1!" << std::endl;
        
        return rv;
    }

    error_t YakClient::yak_peer1_step2(mem_t session_id, const yak_msg_t &in, ecc_point_t &result) {
        
        error_t rv = 0;

        if (0 != check_pk_match(in.pk, peer_addr) || !in.eph_zkp.v(my_pk.get_curve(), in.eph, session_id + mem_t::from_string(peer_addr), 1)) 
        {   
            logger::log(logger::ERROR) << "Check message failed." << std::endl;
            return ub::error(E_BADARG);
        }

        result = (in.pk + in.eph) * (my_sk + my_esk);
        
        // mem_t key = kdf(result);
        logger::log(logger::INFO) << "Client derived key: " << point_to_hex(result) << std::endl;
        return rv;
    }
} // namespace mpc

