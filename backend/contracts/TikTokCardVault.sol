// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {GiftCard} from "./GiftCard.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title TikTokCardVault
 * @notice Vault for storing gift cards sent via TikTok username
 *
 * Flow:
 * 1. A user calls createGiftCardForTikTok in GiftCard.sol
 * 2. The NFT is minted directly to this contract and linked to the TikTok username
 * 3. The recipient verifies ownership of the username off-chain and calls claimCard
 * 4. The contract transfers the NFT to the recipient
 */
contract TikTokCardVault is Ownable, IERC721Receiver {
    GiftCard public giftCardContract;

    mapping(string => uint256[]) public usernameToTokens;
    mapping(uint256 => string) public tokenToUsername;
    mapping(uint256 => bool) public claimedTokens;

    event CardDeposited(uint256 indexed tokenId, string indexed username, address sender);
    event CardClaimed(uint256 indexed tokenId, address indexed claimer, string indexed username);

    modifier onlyGiftCardContract() {
        require(msg.sender == address(giftCardContract), "Only GiftCard can deposit");
        _;
    }

    constructor(address _giftCardAddress) Ownable(msg.sender) {
        require(_giftCardAddress != address(0), "GiftCard address required");
        giftCardContract = GiftCard(_giftCardAddress);
    }

    function depositCardForUsername(
        uint256 tokenId,
        string memory username,
        address sender
    ) external onlyGiftCardContract {
        require(bytes(username).length > 0, "Username cannot be empty");
        require(giftCardContract.ownerOf(tokenId) == address(this), "Vault must own the card");

        usernameToTokens[username].push(tokenId);
        tokenToUsername[tokenId] = username;
        claimedTokens[tokenId] = false;

        emit CardDeposited(tokenId, username, sender);
    }

    function claimCard(
        uint256 tokenId,
        string memory username,
        address claimer
    ) external {
        require(!claimedTokens[tokenId], "Card already claimed");
        require(claimer != address(0), "Invalid claimer address");

        string memory storedUsername = tokenToUsername[tokenId];
        require(keccak256(bytes(storedUsername)) == keccak256(bytes(username)), "Username mismatch");

        claimedTokens[tokenId] = true;

        uint256[] storage tokens = usernameToTokens[username];
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == tokenId) {
                tokens[i] = tokens[tokens.length - 1];
                tokens.pop();
                break;
            }
        }

        giftCardContract.transferFrom(address(this), claimer, tokenId);

        emit CardClaimed(tokenId, claimer, username);
    }

    function getPendingCardsForUsername(string memory username) external view returns (uint256[] memory) {
        return usernameToTokens[username];
    }

    function isCardClaimed(uint256 tokenId) external view returns (bool) {
        return claimedTokens[tokenId];
    }

    function getUsernameForToken(uint256 tokenId) external view returns (string memory) {
        return tokenToUsername[tokenId];
    }

    function setGiftCardContract(address _giftCardAddress) external onlyOwner {
        require(_giftCardAddress != address(0), "GiftCard address required");
        giftCardContract = GiftCard(_giftCardAddress);
    }

    function emergencyRecover(uint256 tokenId, address to) external onlyOwner {
        require(!claimedTokens[tokenId], "Cannot recover claimed card");
        giftCardContract.transferFrom(address(this), to, tokenId);
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
}

