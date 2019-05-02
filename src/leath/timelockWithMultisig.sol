pragma solidity ^0.5.1;

contract TimeLockWithMultiSig {
    modifier after_(uint T) {require (T > 0 && block.number >= T); _;}
    modifier before_(uint T) {require (T == 0 || block.number < T); _;}
    //addresses of clouds, multisig and refund addresses are not neccessarily
    //the same;
    address payable []  C_multiSig;
    address payable [] C_refund;
    
    //time: end of service
    uint T;
    //time: deadline for signing contract
    uint T1;
    
    //amount of deposit
    uint threshold;

    //record of balance
    mapping (address => uint ) public deposits;
    
    //whether the deposit has been paid
    mapping (address => bool) public paid;
    
    //whether all deposit have been collected;
    bool complete;
    
    // for multi-sig, taken from https://github.com/christianlundkvist/simple-multisig
    // EIP712 Precomputed hashes (for multisig):
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)")
    bytes32 constant EIP712DOMAINTYPE_HASH = 0xd87cd6ef79d4e2b95e15ce8abf732db51ec771f1ca2edccf22a46c729ac56472;

    // kekkac256("Simple MultiSig")
    bytes32 constant NAME_HASH = 0xb7a0bfa1b79f2443f4d73ebb9259cddbcd510b18be6fc4da7d1aa7b1786e73e6;

    // kekkac256("1")
    bytes32 constant VERSION_HASH = 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6;

    // kekkac256("MultiSigTransaction(address destination,uint256 value,bytes data,uint256 nonce,address executor,uint256 gasLimit)")
    bytes32 constant TXTYPE_HASH = 0x3ee892349ae4bbe61dce18f95115b5dc02daf49204cc602458cd4c1f540d56d7;

    bytes32 constant SALT = 0x251543af6a222378665a76fe38dbceae4871a070b7fdaf5c6c30cf758dc33cc0;
    bytes32 DOMAIN_SEPARATOR; 
    uint public nonce;                 // mutable state
     
     
        //constructor
    constructor(uint _T, uint _T1, uint _threshold, uint chainId, address payable []  memory _C_multiSig, address payable [] memory _C_refund) public {
        require(_T > 0 && block.number < _T);
        require(_T1 > 0 && block.number < _T1);
        require(_T1 <_T);
        require(_C_multiSig.length == _C_refund.length);
        T=_T;
        T1=_T1;
        threshold=_threshold;
        C_multiSig=_C_multiSig;
        C_refund=_C_refund;
        complete=false;
        
        DOMAIN_SEPARATOR = keccak256(abi.encode(EIP712DOMAINTYPE_HASH,
                                    NAME_HASH,
                                    VERSION_HASH,
                                    chainId,
                                    this,
                                    SALT));
    }
    
    //*********************************************private functions
    
    //check whether the sender is in C_refund (i==1) or C_multiSig(i==0)
    
    function isInAddressList(address _sender, uint i) private view returns (bool ret){
        require(i==0||i==1);
        
        address payable [] memory addresses;
        
        if(i==1){
            addresses=C_refund;
        }else{
            addresses=C_multiSig;
        }
        uint arrayLength = addresses.length;
        
        for(uint j=0;j<arrayLength;j++){
            if (addresses[j]==_sender){
                return true;
            }
            return false;
        }
    }
    
    //check whether all have paid the deposits
    function allPaid() private view returns (bool ret){
        uint arrayLength = C_refund.length;
        
        for(uint i=0;i<arrayLength;i++){
            address C=C_refund[i];
            if (!paid[C]){
                return false;
            }
            return true;
        }
    }
    
    //refund all
    function refund() private{
        uint arrayLength = C_refund.length;
        
        for(uint i=0;i<arrayLength;i++){
            address payable C = C_refund[i];
            uint256 amount=deposits[C];
            if(amount>0){
                deposits[C]=0;
                 C.transfer(amount);
            }
        }
        
    }
    
    //*********************************************public functions
    
    //refund all after T
    function finalize() public after_(T) {
        refund();
            
    }
    
    //refund all have paid after T1, only if the the contract has not been fully
    //initialized
    function noDeal() public after_(T1) {
        if(!complete){
            refund();
        }
            
    }
    
    //pay deposit
    function deposit() before_(T1) public payable { 
        require(isInAddressList(msg.sender,1));
        deposits[msg.sender] += msg.value;
        if (deposits[msg.sender] >= threshold){
            paid[msg.sender]=true;
        }
        
        if(allPaid()){
            complete=true;
        }
    }

  //multisignature, code adapted from https://github.com/christianlundkvist/simple-multisig
  // Note that address recovered from signatures must be strictly increasing, in order to prevent duplicates
  function execute (uint8[] memory sigV, bytes32[] memory sigR, bytes32[] memory sigS, address payable  destination, uint value, bytes memory data, address executor, uint gasLimit) public {
    require(sigR.length == C_multiSig.length);
    require(sigR.length == sigS.length && sigR.length == sigV.length);
    require(executor == msg.sender || executor == address(0));

    // EIP712 scheme: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md
    bytes32 txInputHash = keccak256(abi.encode(TXTYPE_HASH, destination, value, keccak256(data), nonce, executor, gasLimit));
    bytes32 totalHash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, txInputHash));

    address lastAdd = address(0); // cannot have address(0) as an owner
    for (uint i = 0; i < C_multiSig.length; i++) {
      address recovered = ecrecover(totalHash, sigV[i], sigR[i], sigS[i]);
      require(recovered > lastAdd && isInAddressList(recovered,0));
      lastAdd = recovered;
    }

    // If we make it here all signatures are accounted for.
    // The address.call() syntax is no longer recommended, see:
    // https://github.com/ethereum/solidity/issues/2884
    nonce = nonce + 1;
    destination.transfer(address(this).balance);
  }
}
