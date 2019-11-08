#include "yak_client.h"

#include "python2.7/Python.h"

namespace mpc {

error_t get_channel_info(const std::string channel_addr, yak_channel_info_t &info) {
  error_t rv = 0;
  // TODO: ead channel info from blockchain

  return rv;
}

std::string sk_to_pk(std::string sk_hex) {

  bn_t sk = bn_t::from_hex(sk_hex.c_str());

  ecurve_t curve = ecurve_t::find(NID_secp256k1);
  bn_t order = curve.order(); 
  ecc_generator_point_t G = curve.generator();

  ecc_point_t pk = G * sk;
  std::string pk_str = strext::to_hex(pk.get_x().to_bin()) + strext::to_hex(pk.get_y().to_bin()) ;
  return pk_str;
}

ecc_point_t sk_to_pk_point(std::string sk_hex) {

  bn_t sk = bn_t::from_hex(sk_hex.c_str());

  ecurve_t curve = ecurve_t::find(NID_secp256k1);
  bn_t order = curve.order();
  ecc_generator_point_t G = curve.generator();

  ecc_point_t pk = G * sk;

  return pk;
}

ecc_point_t sk_to_pk_point(bn_t sk) {

  ecurve_t curve = ecurve_t::find(NID_secp256k1);
  bn_t order = curve.order();
  ecc_generator_point_t G = curve.generator();

  ecc_point_t pk = G * sk;

  return pk;
}


ecc_point_t hex_to_point(std::string point_hex) {
  std::string x_hex(point_hex, 0, 64), y_hex(point_hex, 64, 64); 
  bn_t x = bn_t::from_hex(x_hex.c_str());
  bn_t y = bn_t::from_hex(y_hex.c_str());

  ecc_point_t point(ecurve_t::find(NID_secp256k1), x, y);
  return point;
}

std::string point_to_hex(ecc_point_t point) {
  std::string x = strext::to_hex(point.get_x().to_bin());
  std::string y = strext::to_hex(point.get_y().to_bin());
  return x + y;
}

std::string pk_to_addr(std::string public_key) {

    Py_Initialize();

    std::string path = "./src/yak";
    std::string chdir_cmd = std::string("sys.path.append(\"") + path + "\")";
    const char* cstr_cmd = chdir_cmd.c_str();
    PyRun_SimpleString("import sys");
    PyRun_SimpleString(cstr_cmd);

    PyObject* moduleName = PyString_FromString("ETH_address"); 
    PyObject* pModule = PyImport_Import(moduleName);

    PyObject* pv = PyObject_GetAttrString(pModule, "pk_to_checksum_addr");

    PyObject* args = PyTuple_New(1);  
    PyObject* arg1 = PyString_FromString(public_key.c_str()); 
    PyTuple_SetItem(args, 0, arg1);

    PyObject* pRet = PyObject_CallObject(pv, args);

    std::string address;
    if (pRet)
    {
      address = PyString_AS_STRING(pRet);
    }
    
    Py_Finalize();

    return address;
}

error_t check_pk_match(const ecc_point_t pk, const std::string addr) {
  std::string x = strext::to_hex(pk.get_x().to_bin());
  std::string y = strext::to_hex(pk.get_y().to_bin());
  std::string _addr = pk_to_addr(x + y);
  return _addr.compare(addr);
}

mem_t kdf(ecc_point_t p) {
  // FIXME: 
  return sha256_t::hash(p);

/*
    unsigned char secret[HASH_SIZE]={0};
    memcpy(secret, p.to_bin(), HASH_SIZE);

    const EVP_MD *md = MD_FUNC;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    unsigned char prk[HASH_SIZE], okm[OUT_LEN];
    size_t outlen = HASH_SIZE, i, ret;


    ret = EVP_PKEY_derive_init(pctx) <= 0
          || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0
          || EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
          || EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, HASH_SIZE) <= 0
          //|| EVP_PKEY_CTX_add1_hkdf_info(pctx, INFO, INFO_LEN) <= 0
          || EVP_PKEY_derive(pctx, prk, &outlen) <= 0;

    if (ret == 0)
    {
        printf("HKDF extract prk:%d\n",outlen);
        for(i=0;i<outlen;i++)
            printf("%02X", prk[i]);
        printf("\n");
    }
    EVP_PKEY_CTX_free(pctx); 

    outlen = OUT_LEN;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    ret = EVP_PKEY_derive_init(pctx) <= 0
          || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0
          || EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
          || EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, HASH_SIZE) <= 0
          || EVP_PKEY_CTX_add1_hkdf_info(pctx, INFO, INFO_LEN) <= 0
          || EVP_PKEY_derive(pctx, okm, &outlen) <= 0;

    if (ret == 0)
    {
        printf("HKDF expand okm:%d\n",outlen);
        for(i=0;i<outlen;i++)
            printf("%02X", okm[i]);
        printf("\n");
    }
    EVP_PKEY_CTX_free(pctx);
*/
}

} //namespace mpc