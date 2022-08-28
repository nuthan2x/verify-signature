//SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.16;

contract verify_SIG{

    function Verify(string memory _message,address  _signer, bytes memory _sig)public pure returns(bool){

        bytes32 messagehash = getmessagehash(_message);
        bytes32 ethsignedhashmessagehash = getethsignedhashmessagehash(messagehash);

        return recover(ethsignedhashmessagehash, _sig) == _signer ;
        
    }

    function getmessagehash(string memory _message) public pure returns(bytes32){
        return keccak256(abi.encodePacked(_message));
    }

    function getethsignedhashmessagehash(bytes32  _messagehash) public pure returns(bytes32){
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",_messagehash));
    }

    function recover(bytes32 ethsignedhashmessagehash,bytes memory _sig) public pure returns(address){
        (bytes32 r,bytes32 s,uint8 v) = split(_sig);

        return ecrecover(ethsignedhashmessagehash,v,r,s);
    }

    function split(bytes memory _sig) public pure returns(bytes32 r,bytes32 s,uint8 v){
        require(_sig.length == 65);
        assembly{
            r:= mload(add(_sig,32))
            s:= mload(add(_sig,64))
            v:= byte(0,mload(add(_sig,96)))

        }
    }

}
