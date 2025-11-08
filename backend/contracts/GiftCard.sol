// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721Enumerable} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./TwitterCardVault.sol";
import "./TwitchCardVault.sol";
import "./TelegramCardVault.sol";
import "./TikTokCardVault.sol";
import "./InstagramCardVault.sol";

contract GiftCard is ERC721Enumerable, Ownable {
    struct GiftCardInfo {
        uint256 amount;
        address token;
        bool redeemed;
        string message;
    }

    IERC20 public usdcToken;
    IERC20 public eurcToken;
    uint256 private nextTokenId;
    mapping(uint256 => GiftCardInfo) public giftCards;
    
    // Vault contract for Twitter cards
    TwitterCardVault public vaultContract;
    
    // Vault contract for Twitch cards
    TwitchCardVault public twitchVaultContract;
    
    // Vault contract for Telegram cards
    TelegramCardVault public telegramVaultContract;

    // Vault contract for TikTok cards
    TikTokCardVault public tiktokVaultContract;

    // Vault contract for Instagram cards
    InstagramCardVault public instagramVaultContract;

    event GiftCardCreated(
        uint256 tokenId,
        address recipient,
        uint256 amount,
        address token,
        string uri,
        string message
    );

    event GiftCardRedeemed(
        uint256 tokenId,
        address redeemer,
        uint256 amount,
        address token
    );
    
    event GiftCardCreatedForTwitter(
        uint256 tokenId,
        string username,
        address sender,
        uint256 amount,
        address token,
        string uri,
        string message
    );
    
    event GiftCardCreatedForTwitch(
        uint256 tokenId,
        string username,
        address sender,
        uint256 amount,
        address token,
        string uri,
        string message
    );

    event GiftCardCreatedForTelegram(
        uint256 tokenId,
        string username,
        address sender,
        uint256 amount,
        address token,
        string uri,
        string message
    );

    event GiftCardCreatedForTikTok(
        uint256 tokenId,
        string username,
        address sender,
        uint256 amount,
        address token,
        string uri,
        string message
    );

    event GiftCardCreatedForInstagram(
        uint256 tokenId,
        string username,
        address sender,
        uint256 amount,
        address token,
        string uri,
        string message
    );

    constructor(address _usdcAddress, address _eurcAddress) ERC721("Sendly Gift Card", "SGC") Ownable(msg.sender) {
        require(_usdcAddress != address(0), "USDC required");
        require(_eurcAddress != address(0), "EURC required");
        usdcToken = IERC20(_usdcAddress);
        eurcToken = IERC20(_eurcAddress);
        nextTokenId = 1;
    }

    function createGiftCard(
        address _recipient,
        uint256 _amount,
        address _token,
        string memory _metadataURI,
        string memory _message
    ) external returns (uint256) {
        require(_recipient != address(0), "bad recipient");
        require(_token == address(usdcToken) || _token == address(eurcToken), "unsupported token");
        require(_amount > 0, "amount=0");

        // pull token from sender
        require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "transferFrom failed");

        uint256 tokenId = nextTokenId++;
        _safeMint(_recipient, tokenId);
        giftCards[tokenId] = GiftCardInfo({amount: _amount, token: _token, redeemed: false, message: _message});

        emit GiftCardCreated(tokenId, _recipient, _amount, _token, _metadataURI, _message);
        return tokenId;
    }

    function redeemGiftCard(uint256 tokenId) external {
        require(_ownerOf(tokenId) != address(0), "no card");
        GiftCardInfo storage info = giftCards[tokenId];
        require(!info.redeemed, "redeemed");
        require(ownerOf(tokenId) == msg.sender, "not owner");

        info.redeemed = true;
        require(IERC20(info.token).transfer(msg.sender, info.amount), "transfer failed");

        emit GiftCardRedeemed(tokenId, msg.sender, info.amount, info.token);
    }

    function getGiftCardInfo(uint256 tokenId) external view returns (GiftCardInfo memory) {
        require(_ownerOf(tokenId) != address(0), "no card");
        return giftCards[tokenId];
    }
    
    /**
     * @notice Create a gift card for a Twitter username and deposit it into vault
     * @param _username The Twitter username (without @)
     * @param _amount The amount of tokens
     * @param _token The token address (USDC or EURC)
     * @param _metadataURI The metadata URI
     * @param _message The message
     * @return The token ID
     */
    function createGiftCardForTwitter(
        string memory _username,
        uint256 _amount,
        address _token,
        string memory _metadataURI,
        string memory _message
    ) external returns (uint256) {
        require(address(vaultContract) != address(0), "Vault not set");
        require(bytes(_username).length > 0, "Username required");
        require(_token == address(usdcToken) || _token == address(eurcToken), "unsupported token");
        require(_amount > 0, "amount=0");

        // Pull token from sender
        require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "transferFrom failed");

        uint256 tokenId = nextTokenId++;
        
        // Mint directly to vault
        _safeMint(address(vaultContract), tokenId);
        giftCards[tokenId] = GiftCardInfo({amount: _amount, token: _token, redeemed: false, message: _message});

        // Register card with vault
        vaultContract.depositCardForUsername(tokenId, _username, msg.sender);

        emit GiftCardCreated(tokenId, address(vaultContract), _amount, _token, _metadataURI, _message);
        emit GiftCardCreatedForTwitter(tokenId, _username, msg.sender, _amount, _token, _metadataURI, _message);
        
        return tokenId;
    }
    
    /**
     * @notice Create a gift card for a Twitch username and deposit it into vault
     * @param _username The Twitch username
     * @param _amount The amount of tokens
     * @param _token The token address (USDC or EURC)
     * @param _metadataURI The metadata URI
     * @param _message The message
     * @return The token ID
     */
    function createGiftCardForTwitch(
        string memory _username,
        uint256 _amount,
        address _token,
        string memory _metadataURI,
        string memory _message
    ) external returns (uint256) {
        require(address(twitchVaultContract) != address(0), "Twitch Vault not set");
        require(bytes(_username).length > 0, "Username required");
        require(_token == address(usdcToken) || _token == address(eurcToken), "unsupported token");
        require(_amount > 0, "amount=0");

        // Pull token from sender
        require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "transferFrom failed");

        uint256 tokenId = nextTokenId++;
        
        // Mint directly to vault
        _safeMint(address(twitchVaultContract), tokenId);
        giftCards[tokenId] = GiftCardInfo({amount: _amount, token: _token, redeemed: false, message: _message});

        // Register card with vault
        twitchVaultContract.depositCardForUsername(tokenId, _username, msg.sender);

        emit GiftCardCreated(tokenId, address(twitchVaultContract), _amount, _token, _metadataURI, _message);
        emit GiftCardCreatedForTwitch(tokenId, _username, msg.sender, _amount, _token, _metadataURI, _message);
        
        return tokenId;
    }
    
    /**
     * @notice Create a gift card for a Telegram username and deposit it into vault
     * @param _username The Telegram username (without @)
     * @param _amount The amount of tokens
     * @param _token The token address (USDC or EURC)
     * @param _metadataURI The metadata URI
     * @param _message The message
     * @return The token ID
     */
    function createGiftCardForTelegram(
        string memory _username,
        uint256 _amount,
        address _token,
        string memory _metadataURI,
        string memory _message
    ) external returns (uint256) {
        require(address(telegramVaultContract) != address(0), "Telegram Vault not set");
        require(bytes(_username).length > 0, "Username required");
        require(_token == address(usdcToken) || _token == address(eurcToken), "unsupported token");
        require(_amount > 0, "amount=0");

        require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "transferFrom failed");

        uint256 tokenId = nextTokenId++;

        _safeMint(address(telegramVaultContract), tokenId);
        giftCards[tokenId] = GiftCardInfo({amount: _amount, token: _token, redeemed: false, message: _message});

        telegramVaultContract.depositCardForUsername(tokenId, _username, msg.sender);

        emit GiftCardCreated(tokenId, address(telegramVaultContract), _amount, _token, _metadataURI, _message);
        emit GiftCardCreatedForTelegram(tokenId, _username, msg.sender, _amount, _token, _metadataURI, _message);

        return tokenId;
    }
    
    /**
     * @notice Create a gift card for a TikTok username and deposit it into vault
     * @param _username The TikTok username (without @)
     * @param _amount The amount of tokens
     * @param _token The token address (USDC or EURC)
     * @param _metadataURI The metadata URI
     * @param _message The message
     * @return The token ID
     */
    function createGiftCardForTikTok(
        string memory _username,
        uint256 _amount,
        address _token,
        string memory _metadataURI,
        string memory _message
    ) external returns (uint256) {
        require(address(tiktokVaultContract) != address(0), "TikTok Vault not set");
        require(bytes(_username).length > 0, "Username required");
        require(_token == address(usdcToken) || _token == address(eurcToken), "unsupported token");
        require(_amount > 0, "amount=0");

        require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "transferFrom failed");

        uint256 tokenId = nextTokenId++;

        _safeMint(address(tiktokVaultContract), tokenId);
        giftCards[tokenId] = GiftCardInfo({amount: _amount, token: _token, redeemed: false, message: _message});

        tiktokVaultContract.depositCardForUsername(tokenId, _username, msg.sender);

        emit GiftCardCreated(tokenId, address(tiktokVaultContract), _amount, _token, _metadataURI, _message);
        emit GiftCardCreatedForTikTok(tokenId, _username, msg.sender, _amount, _token, _metadataURI, _message);

        return tokenId;
    }

    /**
     * @notice Create a gift card for an Instagram username and deposit it into vault
     * @param _username The Instagram username (without @)
     * @param _amount The amount of tokens
     * @param _token The token address (USDC or EURC)
     * @param _metadataURI The metadata URI
     * @param _message The message
     * @return The token ID
     */
    function createGiftCardForInstagram(
        string memory _username,
        uint256 _amount,
        address _token,
        string memory _metadataURI,
        string memory _message
    ) external returns (uint256) {
        require(address(instagramVaultContract) != address(0), "Instagram Vault not set");
        require(bytes(_username).length > 0, "Username required");
        require(_token == address(usdcToken) || _token == address(eurcToken), "unsupported token");
        require(_amount > 0, "amount=0");

        require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "transferFrom failed");

        uint256 tokenId = nextTokenId++;

        _safeMint(address(instagramVaultContract), tokenId);
        giftCards[tokenId] = GiftCardInfo({amount: _amount, token: _token, redeemed: false, message: _message});

        instagramVaultContract.depositCardForUsername(tokenId, _username, msg.sender);

        emit GiftCardCreated(tokenId, address(instagramVaultContract), _amount, _token, _metadataURI, _message);
        emit GiftCardCreatedForInstagram(tokenId, _username, msg.sender, _amount, _token, _metadataURI, _message);

        return tokenId;
    }

    /**
     * @notice Set the vault contract address
     * @param _vaultAddress The vault contract address
     */
    function setVaultContract(address _vaultAddress) external onlyOwner {
        require(_vaultAddress != address(0), "Vault address required");
        vaultContract = TwitterCardVault(_vaultAddress);
    }
    
    /**
     * @notice Set the Twitch vault contract address
     * @param _vaultAddress The Twitch vault contract address
     */
    function setTwitchVaultContract(address _vaultAddress) external onlyOwner {
        require(_vaultAddress != address(0), "Twitch Vault address required");
        twitchVaultContract = TwitchCardVault(_vaultAddress);
    }

    /**
     * @notice Set the Telegram vault contract address
     * @param _vaultAddress The Telegram vault contract address
     */
    function setTelegramVaultContract(address _vaultAddress) external onlyOwner {
        require(_vaultAddress != address(0), "Telegram Vault address required");
        telegramVaultContract = TelegramCardVault(_vaultAddress);
    }

    /**
     * @notice Set the TikTok vault contract address
     * @param _vaultAddress The TikTok vault contract address
     */
    function setTikTokVaultContract(address _vaultAddress) external onlyOwner {
        require(_vaultAddress != address(0), "TikTok Vault address required");
        tiktokVaultContract = TikTokCardVault(_vaultAddress);
    }

    /**
     * @notice Set the Instagram vault contract address
     * @param _vaultAddress The Instagram vault contract address
     */
    function setInstagramVaultContract(address _vaultAddress) external onlyOwner {
        require(_vaultAddress != address(0), "Instagram Vault address required");
        instagramVaultContract = InstagramCardVault(_vaultAddress);
    }
}


