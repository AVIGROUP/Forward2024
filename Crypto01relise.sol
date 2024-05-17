// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

// Import OpenZeppelin contracts
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Vault is Ownable, ReentrancyGuard {
    // Instance of the ERC20 token
    IERC20 public token;

    // Total supply of shares and balance mapping
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // Withdrawal fee percentage (e.g., 2% = 200)
    uint256 public withdrawalFeePercentage;

    // Nonce for signature validation
    mapping(address => bytes32) public nonces;

    // Events
    event Deposit(address indexed user, uint256 amount, uint256 shares);
    event Withdrawal(address indexed user, uint256 amount, uint256 shares);

    // Constructor to initialize the token
    constructor(address _token, uint256 _withdrawalFeePercentage) Ownable(msg.sender) {
        token = IERC20(_token);
        withdrawalFeePercentage = _withdrawalFeePercentage;
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
    function deposit(uint256 _amount) external nonReentrant {
        // Check if user has approved the contract to spend the tokens
        uint256 allowance = token.allowance(msg.sender, address(this));
        require(allowance >= _amount, "Insufficient token allowance");

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

        emit Deposit(msg.sender, _amount, shares);
    }

    // Withdraw function to redeem shares and withdraw tokens
    function withdraw(uint256 _shares, bytes calldata _signature, bytes32 _nonce) external nonReentrant validSig(_signature, _nonce) {
        uint256 amount = (_shares * token.balanceOf(address(this))) / totalSupply;

        // Calculate withdrawal fee
        uint256 withdrawalFee = (amount * withdrawalFeePercentage) / 10000;
        amount -= withdrawalFee;

        // Burn shares from withdrawer
        _burn(msg.sender, _shares);

        // Transfer tokens to withdrawer
        token.transfer(msg.sender, amount);

        emit Withdrawal(msg.sender, amount, _shares);
    }

    // Modifier to validate the signature
    modifier validSig(bytes calldata _signature, bytes32 _nonce) {
        // Calculate the message hash
        bytes32 _messageHash = keccak256(abi.encodePacked(msg.sender, _nonce));

        // Recover signer from the signature
        address signer = ECDSA.recover(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)),
            _signature
        );

        // Ensure signer is the owner and nonce is valid
        require(signer == owner() && nonces[msg.sender] != _nonce, "Invalid signature or nonce");

        // Update the nonce
        nonces[msg.sender] = _nonce;

        _;
    }

    // Function to update the withdrawal fee percentage
    function updateWithdrawalFeePercentage(uint256 _newFeePercentage) external onlyOwner {
        require(_newFeePercentage <= 1000, "Fee percentage cannot exceed 10%"); // Max 10%
        withdrawalFeePercentage = _newFeePercentage;
    }
}
