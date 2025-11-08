// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {GiftCard} from "./GiftCard.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title TwitterCardVault
 * @notice Vault contract for temporarily storing gift cards sent to Twitter usernames
 * 
 * Flow:
 * 1. User creates gift card via createGiftCardForTwitter (in GiftCard contract)
 * 2. Card is minted directly to Vault and registered with username
 * 3. Claimer verifies ownership of Twitter username off-chain and calls claimCard
 * 4. Vault transfers the NFT to claimer's wallet
 */
contract TwitterCardVault is Ownable, IERC721Receiver {
    // Reference to the GiftCard contract
    GiftCard public giftCardContract;
    
    // Mapping from username to array of pending tokenIds
    mapping(string => uint256[]) public usernameToTokens;
    
    // Mapping from tokenId to username
    mapping(uint256 => string) public tokenToUsername;
    
    // Mapping from tokenId to claim status (true = claimed)
    mapping(uint256 => bool) public claimedTokens;
    
    // Events
    event CardDeposited(uint256 indexed tokenId, string indexed username, address sender);
    event CardClaimed(uint256 indexed tokenId, address indexed claimer, string indexed username);
    
    // Modifier to ensure only GiftCard contract can call deposit functions
    modifier onlyGiftCardContract() {
        require(msg.sender == address(giftCardContract), "Only GiftCard can deposit");
        _;
    }
    
    constructor(address _giftCardAddress) Ownable(msg.sender) {
        require(_giftCardAddress != address(0), "GiftCard address required");
        giftCardContract = GiftCard(_giftCardAddress);
    }
    
    /**
     * @notice Deposit a gift card for a Twitter username
     * @dev Only callable by GiftCard contract
     * @param tokenId The token ID of the gift card
     * @param username The Twitter username (without @)
     * @param sender The address that created the card
     */
    function depositCardForUsername(
        uint256 tokenId,
        string memory username,
        address sender
    ) external onlyGiftCardContract {
        require(bytes(username).length > 0, "Username cannot be empty");
        
        // Verify that this contract owns the card
        require(giftCardContract.ownerOf(tokenId) == address(this), "Vault must own the card");
        
        // Add to username mapping
        usernameToTokens[username].push(tokenId);
        tokenToUsername[tokenId] = username;
        claimedTokens[tokenId] = false;
        
        emit CardDeposited(tokenId, username, sender);
    }
    
    /**
     * @notice Claim a gift card by the owner of the Twitter username
     * @dev Claimer must prove ownership of username off-chain before calling
     * @param tokenId The token ID to claim
     * @param username The Twitter username (must match token)
     * @param claimer The address that will receive the card
     */
    function claimCard(
        uint256 tokenId,
        string memory username,
        address claimer
    ) external {
        require(!claimedTokens[tokenId], "Card already claimed");
        require(claimer != address(0), "Invalid claimer address");
        
        // Verify username matches
        string memory storedUsername = tokenToUsername[tokenId];
        require(keccak256(bytes(storedUsername)) == keccak256(bytes(username)), "Username mismatch");
        
        // Mark as claimed
        claimedTokens[tokenId] = true;
        
        // Remove from username's pending list (find and remove)
        uint256[] storage tokens = usernameToTokens[username];
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == tokenId) {
                tokens[i] = tokens[tokens.length - 1];
                tokens.pop();
                break;
            }
        }
        
        // Transfer NFT to claimer
        giftCardContract.transferFrom(address(this), claimer, tokenId);
        
        emit CardClaimed(tokenId, claimer, username);
    }
    
    /**
     * @notice Get all pending token IDs for a username
     * @param username The Twitter username
     * @return Array of pending token IDs
     */
    function getPendingCardsForUsername(string memory username) external view returns (uint256[] memory) {
        return usernameToTokens[username];
    }
    
    /**
     * @notice Check if a card has been claimed
     * @param tokenId The token ID
     * @return true if claimed, false otherwise
     */
    function isCardClaimed(uint256 tokenId) external view returns (bool) {
        return claimedTokens[tokenId];
    }
    
    /**
     * @notice Get the username associated with a token ID
     * @param tokenId The token ID
     * @return The username (empty if not set)
     */
    function getUsernameForToken(uint256 tokenId) external view returns (string memory) {
        return tokenToUsername[tokenId];
    }
    
    /**
     * @notice Update the GiftCard contract address (only owner)
     * @param _giftCardAddress The new GiftCard contract address
     */
    function setGiftCardContract(address _giftCardAddress) external onlyOwner {
        require(_giftCardAddress != address(0), "GiftCard address required");
        giftCardContract = GiftCard(_giftCardAddress);
    }
    
    /**
     * @notice Emergency function to recover stuck NFTs (only owner)
     * @dev Should never be needed if contract works correctly
     * @param tokenId The token ID to recover
     * @param to The address to send to
     */
    function emergencyRecover(uint256 tokenId, address to) external onlyOwner {
        require(!claimedTokens[tokenId], "Cannot recover claimed card");
        giftCardContract.transferFrom(address(this), to, tokenId);
    }
    
    /**
     * @notice Implementation of IERC721Receiver to allow receiving NFTs
     * @param operator The address which initiated the transfer
     * @param from The address from which the token was transferred
     * @param tokenId The token ID being transferred
     * @param data Additional data, unused
     * @return The function selector to indicate successful receipt
     */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes memory data
    ) external pure override returns (bytes4) {
        // Accept all NFTs (will verify ownership in depositCardForUsername)
        return IERC721Receiver.onERC721Received.selector;
    }
}

