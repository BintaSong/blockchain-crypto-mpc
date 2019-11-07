import codecs
import ecdsa
from Crypto.Hash import keccak

def sk_to_pk(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    public_key = codecs.encode(key_bytes, 'hex')
    return public_key

def pk_to_addr(public_key):
    public_key_bytes = codecs.decode(public_key, 'hex')
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(public_key_bytes)
    keccak_digest = keccak_hash.hexdigest()
    # Take last 20 bytes
    wallet_len = 40
    wallet = '0x' + keccak_digest[-wallet_len:]
    return wallet

def checksum_address(address):
    checksum = '0x'
    # Remove '0x' from the address
    address = address[2:]
    address_byte_array = address.encode('utf-8')
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(address_byte_array)
    keccak_digest = keccak_hash.hexdigest()
    for i in range(len(address)):
        address_char = address[i]
        keccak_char = keccak_digest[i]
        if int(keccak_char, 16) >= 8:
            checksum += address_char.upper()
        else:
            checksum += str(address_char)
    return checksum

def pk_to_checksum_addr(public_key):
    public_key_bytes = codecs.decode(public_key, 'hex')
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(public_key_bytes)
    keccak_digest = keccak_hash.hexdigest()
    # Take last 20 bytes
    wallet_len = 40
    wallet = '0x' + keccak_digest[-wallet_len:]
    c_address = checksum_address(wallet)
    #return "ddddd"
    return c_address

'''
address = blocksmith.EthereumWallet.generate_address(key)
print(address)
# 0x1269645a46a3e86c1a3c3de8447092d90f6f04ed

checksum_address = blocksmith.EthereumWallet.checksum_address(address)
print(checksum_address)
# 0x1269645a46A3e86c1a3C3De8447092D90f6F04ED
'''

'''
pk = sk_to_pk("53877FAD07DA5ADDD88C8EA509B10EA35730D89FE06D801CFE6A478C614A7CB4")
print(pk)

addr = pk_to_addr(pk)
print(addr)

c_addr = pk_to_checksum_addr(pk)
print(c_addr)
'''