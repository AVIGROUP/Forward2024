// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

// Import OpenZeppelin contracts
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract Vault is Ownable {
    // Instance of the ERC20 token
    IERC20 public token;

    // Total supply of shares and balance mapping
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // Constructor to initialize the token
    constructor(address _token) Ownable(msg.sender) {
        token = IERC20(_token);
    }

    // Internal function to mint shares
    function _mint(address _to, uint256 _shares) private {
        totalSupply += _shares;
        balanceOf[_to] += _shares;
    }

    // Internal function to burn shares
    function _burn(address _from, uint256 _shares) private {
        totalSupply -= _shares;
        balanceOf[_from] -= _shares;
    }

    // Deposit function to deposit tokens and mint shares
    function deposit(uint256 _amount) external {
        uint256 shares;
        if (totalSupply == 0) {
            shares = _amount; // If no supply, mint same amount of shares
        } else {
            // Calculate shares to mint based on deposited amount
            shares = (_amount * totalSupply) / token.balanceOf(address(this));
        }

        // Mint shares to depositor
        _mint(msg.sender, shares);
        // Transfer tokens from depositor to contract
        token.transferFrom(msg.sender, address(this), _amount);
    }

    // Withdraw function to redeem shares and withdraw tokens
    function withdraw(uint256 _shares, bytes calldata _signature, bytes calldata _nonce, address _adr) external validSig(_signature, _adr, _nonce) {
        uint256 amount =
            (_shares * token.balanceOf(address(this))) / totalSupply;
        // Burn shares from withdrawer
        _burn(_adr, _shares);
        // Transfer tokens to withdrawer
        token.transfer(_adr, amount);
    }

    // Modifier to validate the signature
    modifier validSig(bytes calldata _signature, address _adr, bytes calldata _nonce) {
        // Calculate the message hash
        bytes32 _messageHash = keccak256(abi.encodePacked(_adr, _nonce));
        // Recover signer from the signature
        address signer = ECDSA.recover(
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            ),
            _signature
        );
        // Ensure signer is the owner
        require(signer == owner(), "Invalid signature");
        _;
    }
}
