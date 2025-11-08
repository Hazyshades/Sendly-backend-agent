import { Hono } from 'npm:hono';
import { cors } from 'npm:hono/cors';
import { logger } from 'npm:hono/logger';
import { createClient } from 'npm:@supabase/supabase-js@2';
import { ethers } from 'npm:ethers@6';
import * as kv from './kv_store.tsx';

const app = new Hono();

// CORS middleware - must be first to handle OPTIONS requests
app.use('*', cors({
  origin: '*',
  allowHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  allowMethods: ['POST', 'GET', 'OPTIONS', 'PUT', 'DELETE', 'PATCH'],
  credentials: false,
  maxAge: 86400,
  exposeHeaders: ['Content-Length', 'Content-Type'],
}));

// Explicit OPTIONS request handling BEFORE any other handlers
app.options('*', async (c) => {
  return c.noContent(204);
});

app.use('*', logger(console.log));

// Health check endpoint - works without checking environment variables
app.get('/', async (c) => {
  return c.json({ 
    status: 'ok', 
    message: 'Edge Function is running',
    timestamp: new Date().toISOString(),
    routes: [
      'POST /gift-cards/twitter/create',
      'GET /gift-cards/twitter/:username',
      'GET /gift-cards/twitter/by-token/:tokenId',
      'POST /gift-cards/twitter/:tokenId/claim',
      'POST /gift-cards/twitch/create',
      'GET /gift-cards/twitch/:username',
      'GET /gift-cards/twitch/by-token/:tokenId',
      'POST /gift-cards/twitch/:tokenId/claim',
      'POST /gift-cards/telegram/create',
      'GET /gift-cards/telegram/:username',
      'GET /gift-cards/telegram/by-token/:tokenId',
      'POST /gift-cards/telegram/:tokenId/claim',
      'POST /contacts/get-saved-token',
      'POST /contacts/save-token',
      'POST /contacts/get-twitch-token',
      'POST /contacts/sync',
      'POST /wallets/link-telegram'
    ]
  });
});

// Environment variables - checked later when creating client
let supabaseUrl: string | undefined;
let supabaseKey: string | undefined;
let supabase: ReturnType<typeof createClient> | null = null;

function getSupabaseClient() {
  if (!supabase) {
    supabaseUrl = Deno.env.get('SUPABASE_URL');
    supabaseKey = Deno.env.get('SERVICE_ROLE_KEY');
    
    if (!supabaseUrl) {
      throw new Error('SUPABASE_URL is not set in environment variables');
    }
    
    if (!supabaseKey) {
      throw new Error(
        'SERVICE_ROLE_KEY is not set. ' +
        'Please add it in Supabase Dashboard: Edge Functions → Functions Secrets → Add new secret. ' +
        'Key name: SERVICE_ROLE_KEY (without SUPABASE_ prefix). ' +
        'Value: your service_role key from Settings → API → Project API keys → service_role'
      );
    }
    
    supabase = createClient(supabaseUrl, supabaseKey);
  }
  return supabase;
}

// Helper function to verify user authentication
async function verifyUser(request: Request) {
  const accessToken = request.headers.get('Authorization')?.split(' ')[1];
  if (!accessToken) {
    return { user: null, error: 'No access token provided' };
  }
  
  const client = getSupabaseClient();
  const { data: { user }, error } = await client.auth.getUser(accessToken);
  return { user, error };
}

function normalizeWalletAddress(address: string | null | undefined) {
  return typeof address === 'string' ? address.trim().toLowerCase() : null;
}

function normalizeBlockchain(blockchain: string | null | undefined) {
  return typeof blockchain === 'string' ? blockchain.trim().toUpperCase() : null;
}

function normalizeTelegramId(telegramId: string | number | null | undefined) {
  if (telegramId === null || telegramId === undefined) return null;
  return String(telegramId).trim();
}

function normalizePrivyUserId(userId: string | null | undefined) {
  if (!userId) return null;
  return userId.startsWith('did:privy:') ? userId.replace('did:privy:', '') : userId;
}

async function verifyWalletOwnershipWithSignature(expectedAddresses: string | string[], message?: string, signature?: string) {
  if (!message || !signature) {
    return { success: false, reason: 'missing_signature' } as const;
  }

  const normalizedExpected = (Array.isArray(expectedAddresses) ? expectedAddresses : [expectedAddresses])
    .filter((address) => typeof address === 'string' && address.trim().length > 0)
    .map((address) => address.toLowerCase());

  if (normalizedExpected.length === 0) {
    return { success: false, reason: 'no_expected_addresses' } as const;
  }

  try {
    const recovered = ethers.verifyMessage(message, signature);
    if (!recovered) {
      return { success: false, reason: 'no_recovered_address' } as const;
    }

    const normalizedRecovered = recovered.toLowerCase();
    const matchedAddress = normalizedExpected.find((expected) => expected === normalizedRecovered);

    return {
      success: Boolean(matchedAddress),
      reason: matchedAddress ? 'verified' : 'address_mismatch',
      recoveredAddress: normalizedRecovered,
      matchedAddress,
      expectedAddresses: normalizedExpected,
    } as const;
  } catch (error) {
    console.warn('Signature verification failed:', error);
    return { success: false, reason: 'verification_error', error: error instanceof Error ? error.message : String(error) } as const;
  }
}

interface PrivyCredentials {
  appId: string;
  secret: string;
}

function getPrivyCredentials(): PrivyCredentials | null {
  const appId = Deno.env.get('PRIVY_APP_ID');
  const secret = Deno.env.get('PRIVY_APP_SECRET') || Deno.env.get('PRIVY_API_KEY');

  if (!appId || !secret) {
    return null;
  }

  return { appId, secret };
}

async function fetchPrivyUserById(userId: string) {
  const credentials = getPrivyCredentials();

  if (!credentials) {
    return { success: false as const, reason: 'missing_credentials' as const };
  }

  const normalizedUserId = normalizePrivyUserId(userId);
  if (!normalizedUserId) {
    return { success: false as const, reason: 'invalid_user_id' as const };
  }

  const headers = {
    'Authorization': `Basic ${btoa(`${credentials.appId}:${credentials.secret}`)}`,
    'privy-app-id': credentials.appId,
    'Content-Type': 'application/json',
  } as const;

  const endpoints = [
    `https://auth.privy.io/api/v1/apps/${credentials.appId}/users/${normalizedUserId}`,
    `https://auth.privy.io/api/v1/users/${normalizedUserId}`
  ];

  for (const endpoint of endpoints) {
    try {
      const response = await fetch(endpoint, { method: 'GET', headers });
      if (!response.ok) {
        const errorText = await response.text();
        console.warn('Privy API non-OK response:', response.status, errorText.substring(0, 200));
        continue;
      }

      const data = await response.json();
      return { success: true as const, user: data, endpoint };
    } catch (error) {
      console.error('Error fetching Privy user:', error);
    }
  }

  return { success: false as const, reason: 'not_found' as const };
}

function extractPrivyWalletAddresses(userData: any): string[] {
  const addresses = new Set<string>();

  if (!userData) {
    return [];
  }

  const maybeAddAddress = (value: any) => {
    if (typeof value === 'string' && value.startsWith('0x') && value.length === 42) {
      addresses.add(value.toLowerCase());
    }
  };

  const walletsSources = [
    userData.wallets,
    userData.accounts,
    userData.linked_accounts,
    userData.linkedAccounts,
    userData.data,
  ];

  for (const source of walletsSources) {
    if (!Array.isArray(source)) continue;
    for (const entry of source) {
      if (!entry || typeof entry !== 'object') continue;
      if (entry.type && typeof entry.type === 'string' && entry.type.toLowerCase().includes('wallet')) {
        maybeAddAddress(entry.address || entry.walletAddress || entry.subject || entry.pubkey || entry.publicAddress);
      }
      if (entry.address) {
        maybeAddAddress(entry.address);
      }
      if (entry.wallet && entry.wallet.address) {
        maybeAddAddress(entry.wallet.address);
      }
      if (entry.publicAddress) {
        maybeAddAddress(entry.publicAddress);
      }
    }
  }

  if (userData.wallet && typeof userData.wallet === 'object') {
    maybeAddAddress(userData.wallet.address);
  }

  return Array.from(addresses);
}

function extractPrivyTelegramIds(userData: any): string[] {
  const ids = new Set<string>();

  const maybeAdd = (value: any) => {
    if (value === null || value === undefined) return;
    const normalized = String(value).trim();
    if (normalized.length > 0) {
      ids.add(normalized);
    }
  };

  if (!userData) {
    return [];
  }

  if (userData.telegram) {
    maybeAdd(userData.telegram.telegramUserId || userData.telegram.id || userData.telegram.telegram_user_id);
  }

  const linkedSources = [
    userData.linked_accounts,
    userData.linkedAccounts,
    userData.accounts,
    userData.data,
  ];

  for (const source of linkedSources) {
    if (!Array.isArray(source)) continue;
    for (const entry of source) {
      if (!entry || typeof entry !== 'object') continue;
      const type = (entry.type || entry.provider || entry.providerType || '').toString().toLowerCase();
      if (type.includes('telegram')) {
        maybeAdd(entry.telegramUserId || entry.subject || entry.id || entry.identifier);
      }
    }
  }

  return Array.from(ids);
}

async function verifyWalletOwnershipWithPrivy(userId: string, walletAddress: string) {
  const fetchResult = await fetchPrivyUserById(userId);

  if (!fetchResult.success) {
    return { success: false as const, reason: fetchResult.reason };
  }

  const addresses = extractPrivyWalletAddresses(fetchResult.user);
  const normalizedWallet = walletAddress.toLowerCase();
  const matched = addresses.includes(normalizedWallet);

  return {
    success: matched as const,
    reason: matched ? 'verified' as const : 'address_not_found' as const,
    addresses,
    user: fetchResult.user,
    endpoint: fetchResult.endpoint,
  };
}

// Sign up endpoint
app.post('/signup', async (c) => {
  try {
    const { email, password, name } = await c.req.json();
    
    const client = getSupabaseClient();
    const { data, error } = await client.auth.admin.createUser({
      email,
      password,
      user_metadata: { name },
      // Automatically confirm the user's email since an email server hasn't been configured.
      email_confirm: true
    });

    if (error) {
      console.log(`Signup error: ${error.message}`);
      return c.json({ error: error.message }, 400);
    }

    return c.json({ user: data.user });
  } catch (error) {
    console.log(`Server error during signup: ${error}`);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Create gift card endpoint
app.post('/gift-cards', async (c) => {
  try {
    // TODO: Add authentication when auth system is ready
    // const { user, error: authError } = await verifyUser(c.req.raw);
    // if (!user) {
    //   return c.json({ error: 'Unauthorized' }, 401);
    // }

    const cardData = await c.req.json();
    const cardId = `GIFT${Date.now()}${Math.random().toString(36).substr(2, 4).toUpperCase()}`;
    
    const giftCard = {
      id: cardId,
      sender_id: 'temp_user', // TODO: Replace with actual user ID
      sender_address: cardData.senderAddress,
      recipient_address: cardData.recipientAddress,
      amount: cardData.amount,
      currency: cardData.currency,
      design: cardData.design,
      message: cardData.message,
      secret_message: cardData.secretMessage || '',
      has_timer: cardData.hasTimer || false,
      timer_hours: cardData.timerHours || 0,
      has_password: cardData.hasPassword || false,
      password_hash: cardData.password ? await hashPassword(cardData.password) : '',
      expiry_days: cardData.expiryDays || 7,
      custom_image: cardData.customImage || '',
      nft_cover: cardData.nftCover || '',
      status: 'active',
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + (cardData.expiryDays || 7) * 24 * 60 * 60 * 1000).toISOString(),
      qr_code: `sendly://redeem/${cardId}`,
      tx_hash: cardData.txHash || ''
    };

    await kv.set(`gift_card:${cardId}`, giftCard);
    await kv.set(`user_sent:temp_user:${cardId}`, { card_id: cardId, created_at: giftCard.created_at });
    
    // Add to analytics
    const userStats = await kv.get(`user_stats:temp_user`) || { 
      total_sent: 0, 
      total_received: 0, 
      cards_sent: 0, 
      cards_received: 0 
    };
    userStats.total_sent += parseFloat(cardData.amount);
    userStats.cards_sent += 1;
    await kv.set(`user_stats:temp_user`, userStats);

    return c.json({ card: giftCard });
  } catch (error) {
    console.log(`Error creating gift card: ${error}`);
    return c.json({ error: 'Failed to create gift card' }, 500);
  }
});

// Get user's gift cards
app.get('/gift-cards', async (c) => {
  try {
    // TODO: Add authentication when auth system is ready
    // const { user, error: authError } = await verifyUser(c.req.raw);
    // if (!user) {
    //   return c.json({ error: 'Unauthorized' }, 401);
    // }

    const type = c.req.query('type') || 'sent';
    const prefix = type === 'sent' ? `user_sent:temp_user:` : `user_received:temp_user:`;
    
    const cardRefs = await kv.getByPrefix(prefix);
    const cards = [];
    
    for (const ref of cardRefs) {
      const card = await kv.get(`gift_card:${ref.card_id}`);
      if (card) {
        cards.push(card);
      }
    }

    return c.json({ cards: cards.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()) });
  } catch (error) {
    console.log(`Error fetching gift cards: ${error}`);
    return c.json({ error: 'Failed to fetch gift cards' }, 500);
  }
});

// Get gift card details
app.get('/gift-cards/:cardId', async (c) => {
  try {
    const cardId = c.req.param('cardId');
    const card = await kv.get(`gift_card:${cardId}`);
    
    if (!card) {
      return c.json({ error: 'Gift card not found' }, 404);
    }

    // Check if card is expired
    if (new Date() > new Date(card.expires_at)) {
      card.status = 'expired';
      await kv.set(`gift_card:${cardId}`, card);
    }

    // Remove sensitive information
    const publicCard = { ...card };
    delete publicCard.password_hash;
    
    return c.json({ card: publicCard });
  } catch (error) {
    console.log(`Error fetching gift card: ${error}`);
    return c.json({ error: 'Failed to fetch gift card' }, 500);
  }
});

// Redeem gift card
app.post('/gift-cards/:cardId/redeem', async (c) => {
  try {
    // TODO: Add authentication when auth system is ready
    // const { user, error: authError } = await verifyUser(c.req.raw);
    // if (!user) {
    //   return c.json({ error: 'Unauthorized' }, 401);
    // }

    const cardId = c.req.param('cardId');
    const { password, recipientAddress } = await c.req.json();
    
    const card = await kv.get(`gift_card:${cardId}`);
    if (!card) {
      return c.json({ error: 'Gift card not found' }, 404);
    }

    if (card.status !== 'active') {
      return c.json({ error: `Gift card is ${card.status}` }, 400);
    }

    if (new Date() > new Date(card.expires_at)) {
      card.status = 'expired';
      await kv.set(`gift_card:${cardId}`, card);
      return c.json({ error: 'Gift card has expired' }, 400);
    }

    // Check timer
    if (card.has_timer && card.timer_hours > 0) {
      const createdTime = new Date(card.created_at).getTime();
      const now = Date.now();
      const hoursElapsed = (now - createdTime) / (1000 * 60 * 60);
      
      if (hoursElapsed < card.timer_hours) {
        return c.json({ error: 'Gift card is still locked by timer' }, 400);
      }
    }

    // Check password
    if (card.has_password && card.password_hash) {
      if (!password) {
        return c.json({ error: 'Password required' }, 400);
      }
      
      const isValidPassword = await verifyPassword(password, card.password_hash);
      if (!isValidPassword) {
        return c.json({ error: 'Invalid password' }, 400);
      }
    }

    // Mark as redeemed
    card.status = 'redeemed';
    card.redeemed_at = new Date().toISOString();
    card.redeemed_by = 'temp_user'; // TODO: Replace with actual user ID
    card.redeemed_address = recipientAddress;
    
    await kv.set(`gift_card:${cardId}`, card);
    await kv.set(`user_received:temp_user:${cardId}`, { card_id: cardId, redeemed_at: card.redeemed_at });

    // Update analytics
    const userStats = await kv.get(`user_stats:temp_user`) || { 
      total_sent: 0, 
      total_received: 0, 
      cards_sent: 0, 
      cards_received: 0 
    };
    userStats.total_received += parseFloat(card.amount);
    userStats.cards_received += 1;
    await kv.set(`user_stats:temp_user`, userStats);

    // Create transaction record
    const transaction = {
      id: `tx_${Date.now()}`,
      user_id: 'temp_user', // Temporary for testing
      card_id: cardId,
      type: 'redeemed',
      amount: card.amount,
      currency: card.currency,
      counterpart: card.sender_address,
      message: card.message,
      status: 'completed',
      timestamp: new Date().toISOString(),
      tx_hash: card.tx_hash || ''
    };
    
    await kv.set(`transaction:${transaction.id}`, transaction);
    await kv.set(`user_transactions:temp_user:${transaction.id}`, { transaction_id: transaction.id, timestamp: transaction.timestamp });

    return c.json({ 
      card: card,
      secret_message: card.secret_message,
      transaction: transaction 
    });
  } catch (error) {
    console.log(`Error redeeming gift card: ${error}`);
    return c.json({ error: 'Failed to redeem gift card' }, 500);
  }
});

// Get user analytics
app.get('/analytics', async (c) => {
  try {
    // TODO: Add authentication when auth system is ready
    // const { user, error: authError } = await verifyUser(c.req.raw);
    // if (!user) {
    //   return c.json({ error: 'Unauthorized' }, 401);
    // }

    const stats = await kv.get(`user_stats:temp_user`) || { 
      total_sent: 0, 
      total_received: 0, 
      cards_sent: 0, 
      cards_received: 0 
    };

    const analytics = {
      ...stats,
      total_redeemed: stats.total_received,
      average_amount: stats.cards_sent > 0 ? (stats.total_sent / stats.cards_sent).toFixed(2) : '0',
      top_currency: 'USDC' // Could be calculated from actual data
    };

    return c.json({ analytics });
  } catch (error) {
    console.log(`Error fetching analytics: ${error}`);
    return c.json({ error: 'Failed to fetch analytics' }, 500);
  }
});

// Get user transactions
app.get('/transactions', async (c) => {
  try {
    // TODO: Add authentication when auth system is ready
    // const { user, error: authError } = await verifyUser(c.req.raw);
    // if (!user) {
    //   return c.json({ error: 'Unauthorized' }, 401);
    // }

    const transactionRefs = await kv.getByPrefix(`user_transactions:temp_user:`);
    const transactions = [];
    
    for (const ref of transactionRefs) {
      const transaction = await kv.get(`transaction:${ref.transaction_id}`);
      if (transaction) {
        transactions.push(transaction);
      }
    }

    return c.json({ 
      transactions: transactions.sort((a, b) => 
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      ) 
    });
  } catch (error) {
    console.log(`Error fetching transactions: ${error}`);
    return c.json({ error: 'Failed to fetch transactions' }, 500);
  }
});

// Revoke gift card
app.post('/gift-cards/:cardId/revoke', async (c) => {
  try {
    // TODO: Add authentication when auth system is ready
    // const { user, error: authError } = await verifyUser(c.req.raw);
    // if (!user) {
    //   return c.json({ error: 'Unauthorized' }, 401);
    // }

    const cardId = c.req.param('cardId');
    const card = await kv.get(`gift_card:${cardId}`);
    
    if (!card) {
      return c.json({ error: 'Gift card not found' }, 404);
    }

    // Temporarily allow anyone to revoke for testing
    // if (card.sender_id !== user.id) {
    //   return c.json({ error: 'Only the sender can revoke this card' }, 403);
    // }

    if (card.status !== 'active') {
      return c.json({ error: 'Can only revoke active cards' }, 400);
    }

    card.status = 'revoked';
    card.revoked_at = new Date().toISOString();
    
    await kv.set(`gift_card:${cardId}`, card);

    return c.json({ card });
  } catch (error) {
    console.log(`Error revoking gift card: ${error}`);
    return c.json({ error: 'Failed to revoke gift card' }, 500);
  }
});

// Helper functions for password hashing
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const passwordHash = await hashPassword(password);
  return passwordHash === hash;
}

// Twitter gift card endpoints
// 
// New architecture with Vault contract:
// - Main state (username, tokenId, claimed status) is stored on blockchain in TwitterCardVault
// - KV is used only for additional metadata (message, metadataUri, design, amount, currency)
// - Frontend loads pending cards from Vault contract, then enriches with metadata from KV

// Create Twitter card mapping (saves only metadata to KV)
app.post('/gift-cards/twitter/create', async (c) => {
  try {
    console.log('Received request to create Twitter card mapping');
    const body = await c.req.json().catch((err) => {
      console.error('Failed to parse request body:', err);
      return {};
    });
    
    console.log('Request body:', JSON.stringify(body));
    const { tokenId, username, temporaryOwner, senderAddress, amount, currency, message, metadataUri } = body;
    
    if (!tokenId || !username) {
      console.error('Missing required fields:', { tokenId: !!tokenId, username: !!username });
      return c.json({ 
        error: 'Missing required fields',
        required: ['tokenId', 'username']
      }, 400);
    }
    
    const normalizedUsername = username.toLowerCase().replace('@', '');
    console.log('Creating mapping for:', { tokenId, normalizedUsername });
    
    // temporaryOwner is now optional (for backward compatibility)
    // In new implementation, Vault contract owns NFT, not temporaryOwner
    const twitterCardMapping = {
      tokenId: tokenId.toString(),
      username: normalizedUsername,
      temporaryOwner: temporaryOwner || '', // Empty string for Vault cards
      senderAddress: senderAddress || temporaryOwner || '',
      amount: amount || '0',
      currency: currency || 'USDC',
      message: message || '',
      metadataUri: metadataUri || '',
      status: 'pending',
      createdAt: new Date().toISOString(),
      claimedAt: null,
      realOwner: null
    };
    
    console.log('Saving to KV store...');
    // Save full card metadata
    await kv.set(`twitter_card:${tokenId}`, twitterCardMapping);
    // Save index for searching cards by username (used in GET /gift-cards/twitter/:username)
    await kv.set(`twitter_cards:${normalizedUsername}:${tokenId}`, { tokenId: tokenId.toString(), createdAt: twitterCardMapping.createdAt });
    console.log('Successfully saved Twitter card mapping');
    
    return c.json({ success: true, mapping: twitterCardMapping });
  } catch (error) {
    console.error(`Error creating Twitter card mapping:`, error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const errorStack = error instanceof Error ? error.stack : undefined;
    console.error('Error stack:', errorStack);
    return c.json({ 
      error: 'Failed to create Twitter card mapping',
      details: errorMessage 
    }, 500);
  }
});

// Get pending Twitter cards for a username
app.get('/gift-cards/twitter/:username', async (c) => {
  try {
    const username = c.req.param('username').toLowerCase().replace('@', '');
    
    const cardRefs = await kv.getByPrefix(`twitter_cards:${username}:`);
    
    const pendingCards = [];
    for (const ref of cardRefs) {
      const mapping = await kv.get(`twitter_card:${ref.tokenId}`);
      if (mapping && mapping.status === 'pending') {
        pendingCards.push(mapping);
      }
    }
    
    return c.json({ 
      cards: pendingCards.sort((a, b) => 
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      ) 
    });
  } catch (error) {
    console.log(`Error fetching Twitter cards: ${error}`);
    return c.json({ error: 'Failed to fetch Twitter cards' }, 500);
  }
});

// Get Twitter card mapping by tokenId
app.get('/gift-cards/twitter/by-token/:tokenId', async (c) => {
  try {
    const tokenId = c.req.param('tokenId');
    const mapping = await kv.get(`twitter_card:${tokenId}`);
    
    if (!mapping) {
      return c.json({ error: 'Twitter card mapping not found' }, 404);
    }
    
    return c.json({ mapping });
  } catch (error) {
    console.log(`Error fetching Twitter card mapping: ${error}`);
    return c.json({ error: 'Failed to fetch Twitter card mapping' }, 500);
  }
});

// Claim Twitter card
app.post('/gift-cards/twitter/:tokenId/claim', async (c) => {
  try {
    const tokenId = c.req.param('tokenId');
    const { username, walletAddress } = await c.req.json();
    
    if (!username || !walletAddress) {
      return c.json({ error: 'Missing username or wallet address' }, 400);
    }
    
    const normalizedUsername = username.toLowerCase().replace('@', '');
    const mapping = await kv.get(`twitter_card:${tokenId}`);
    
    if (!mapping) {
      return c.json({ error: 'Twitter card mapping not found' }, 404);
    }
    
    if (mapping.status !== 'pending') {
      return c.json({ error: `Card is already ${mapping.status}` }, 400);
    }
    
    const mappingUsername = mapping.username.toLowerCase().replace('@', '');
    
    if (normalizedUsername !== mappingUsername) {
      return c.json({ error: 'Username mismatch. This card is not for your Twitter account' }, 403);
    }
    
    mapping.status = 'claimed';
    mapping.realOwner = walletAddress;
    mapping.claimedAt = new Date().toISOString();
    
    await kv.set(`twitter_card:${tokenId}`, mapping);
    
    return c.json({ 
      success: true, 
      mapping,
      message: 'Card claimed successfully. Transfer the NFT to complete the process.'
    });
  } catch (error) {
    console.log(`Error claiming Twitter card: ${error}`);
    return c.json({ error: 'Failed to claim Twitter card' }, 500);
  }
});

// Twitch gift card endpoints
// Similar to Twitter, uses TwitchCardVault contract

// Create Twitch card mapping (saves only metadata to KV)
app.post('/gift-cards/twitch/create', async (c) => {
  try {
    console.log('Received request to create Twitch card mapping');
    const body = await c.req.json().catch((err) => {
      console.error('Failed to parse request body:', err);
      return {};
    });
    
    console.log('Request body:', JSON.stringify(body));
    const { tokenId, username, temporaryOwner, senderAddress, amount, currency, message, metadataUri } = body;
    
    if (!tokenId || !username) {
      console.error('Missing required fields:', { tokenId: !!tokenId, username: !!username });
      return c.json({ 
        error: 'Missing required fields',
        required: ['tokenId', 'username']
      }, 400);
    }
    
    const normalizedUsername = username.toLowerCase().trim();
    console.log('Creating Twitch mapping for:', { tokenId, normalizedUsername });
    
    const twitchCardMapping = {
      tokenId: tokenId.toString(),
      username: normalizedUsername,
      temporaryOwner: temporaryOwner || '',
      senderAddress: senderAddress || temporaryOwner || '',
      amount: amount || '0',
      currency: currency || 'USDC',
      message: message || '',
      metadataUri: metadataUri || '',
      status: 'pending',
      createdAt: new Date().toISOString(),
      claimedAt: null,
      realOwner: null
    };
    
    console.log('Saving to KV store...');
    await kv.set(`twitch_card:${tokenId}`, twitchCardMapping);
    await kv.set(`twitch_cards:${normalizedUsername}:${tokenId}`, { tokenId: tokenId.toString(), createdAt: twitchCardMapping.createdAt });
    console.log('Successfully saved Twitch card mapping');
    
    return c.json({ success: true, mapping: twitchCardMapping });
  } catch (error) {
    console.error(`Error creating Twitch card mapping:`, error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ 
      error: 'Failed to create Twitch card mapping',
      details: errorMessage 
    }, 500);
  }
});

// Get pending Twitch cards for a username
app.get('/gift-cards/twitch/:username', async (c) => {
  try {
    const username = c.req.param('username').toLowerCase().trim();
    
    const cardRefs = await kv.getByPrefix(`twitch_cards:${username}:`);
    
    const pendingCards = [];
    for (const ref of cardRefs) {
      const mapping = await kv.get(`twitch_card:${ref.tokenId}`);
      if (mapping && mapping.status === 'pending') {
        pendingCards.push(mapping);
      }
    }
    
    return c.json({ 
      cards: pendingCards.sort((a, b) => 
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      ) 
    });
  } catch (error) {
    console.log(`Error fetching Twitch cards: ${error}`);
    return c.json({ error: 'Failed to fetch Twitch cards' }, 500);
  }
});

// Get Twitch card mapping by tokenId
app.get('/gift-cards/twitch/by-token/:tokenId', async (c) => {
  try {
    const tokenId = c.req.param('tokenId');
    const mapping = await kv.get(`twitch_card:${tokenId}`);
    
    if (!mapping) {
      return c.json({ error: 'Twitch card mapping not found' }, 404);
    }
    
    return c.json({ mapping });
  } catch (error) {
    console.log(`Error fetching Twitch card mapping: ${error}`);
    return c.json({ error: 'Failed to fetch Twitch card mapping' }, 500);
  }
});

// Claim Twitch card
app.post('/gift-cards/twitch/:tokenId/claim', async (c) => {
  try {
    const tokenId = c.req.param('tokenId');
    const { username, walletAddress } = await c.req.json();
    
    if (!username || !walletAddress) {
      return c.json({ error: 'Missing username or wallet address' }, 400);
    }
    
    const normalizedUsername = username.toLowerCase().trim();
    const mapping = await kv.get(`twitch_card:${tokenId}`);
    
    if (!mapping) {
      return c.json({ error: 'Twitch card mapping not found' }, 404);
    }
    
    if (mapping.status !== 'pending') {
      return c.json({ error: `Card is already ${mapping.status}` }, 400);
    }
    
    const mappingUsername = mapping.username.toLowerCase().trim();
    
    if (normalizedUsername !== mappingUsername) {
      return c.json({ error: 'Username mismatch. This card is not for your Twitch account' }, 403);
    }
    
    mapping.status = 'claimed';
    mapping.realOwner = walletAddress;
    mapping.claimedAt = new Date().toISOString();
    
    await kv.set(`twitch_card:${tokenId}`, mapping);
    
    return c.json({ 
      success: true, 
      mapping,
      message: 'Card claimed successfully. Transfer the NFT to complete the process.'
    });
  } catch (error) {
    console.log(`Error claiming Twitch card: ${error}`);
    return c.json({ error: 'Failed to claim Twitch card' }, 500);
  }
});

// Telegram gift card endpoints - similar structure to Twitter/Twitch
app.post('/gift-cards/telegram/create', async (c) => {
  try {
    console.log('Received request to create Telegram card mapping');
    const body = await c.req.json().catch((err) => {
      console.error('Failed to parse request body:', err);
      return {};
    });

    const { tokenId, username, temporaryOwner, senderAddress, amount, currency, message, metadataUri } = body;

    if (!tokenId || !username) {
      console.error('Missing required fields for Telegram mapping');
      return c.json({
        error: 'Missing required fields',
        required: ['tokenId', 'username']
      }, 400);
    }

    const normalizedUsername = username.toLowerCase().replace(/^@/, '').trim();
    console.log('Creating Telegram mapping for:', { tokenId, normalizedUsername });

    const telegramCardMapping = {
      tokenId: tokenId.toString(),
      username: normalizedUsername,
      temporaryOwner: temporaryOwner || '',
      senderAddress: senderAddress || temporaryOwner || '',
      amount: amount || '0',
      currency: currency || 'USDC',
      message: message || '',
      metadataUri: metadataUri || '',
      status: 'pending',
      createdAt: new Date().toISOString(),
      claimedAt: null,
      realOwner: null
    };

    await kv.set(`telegram_card:${tokenId}`, telegramCardMapping);
    await kv.set(`telegram_cards:${normalizedUsername}:${tokenId}`, { tokenId: tokenId.toString(), createdAt: telegramCardMapping.createdAt });

    return c.json({ success: true, mapping: telegramCardMapping });
  } catch (error) {
    console.error(`Error creating Telegram card mapping:`, error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({
      error: 'Failed to create Telegram card mapping',
      details: errorMessage
    }, 500);
  }
});

app.get('/gift-cards/telegram/:username', async (c) => {
  try {
    const username = c.req.param('username').toLowerCase().replace(/^@/, '').trim();
    const cardRefs = await kv.getByPrefix(`telegram_cards:${username}:`);

    const pendingCards = [];
    for (const ref of cardRefs) {
      const mapping = await kv.get(`telegram_card:${ref.tokenId}`);
      if (mapping && mapping.status === 'pending') {
        pendingCards.push(mapping);
      }
    }

    pendingCards.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    return c.json({ cards: pendingCards });
  } catch (error) {
    console.log(`Error fetching Telegram cards: ${error}`);
    return c.json({ error: 'Failed to fetch Telegram cards' }, 500);
  }
});

app.get('/gift-cards/telegram/by-token/:tokenId', async (c) => {
  try {
    const tokenId = c.req.param('tokenId');
    const mapping = await kv.get(`telegram_card:${tokenId}`);

    if (!mapping) {
      return c.json({ error: 'Telegram card mapping not found' }, 404);
    }

    return c.json({ mapping });
  } catch (error) {
    console.log(`Error fetching Telegram card mapping: ${error}`);
    return c.json({ error: 'Failed to fetch Telegram card mapping' }, 500);
  }
});

app.post('/gift-cards/telegram/:tokenId/claim', async (c) => {
  try {
    const tokenId = c.req.param('tokenId');
    const { username, walletAddress } = await c.req.json();

    if (!username || !walletAddress) {
      return c.json({ error: 'Missing username or wallet address' }, 400);
    }

    const normalizedUsername = username.toLowerCase().replace(/^@/, '').trim();
    const mapping = await kv.get(`telegram_card:${tokenId}`);

    if (!mapping) {
      return c.json({ error: 'Telegram card mapping not found' }, 404);
    }

    if (mapping.status !== 'pending') {
      return c.json({ error: `Card is already ${mapping.status}` }, 400);
    }

    const mappingUsername = (mapping.username || '').toLowerCase().replace(/^@/, '').trim();

    if (normalizedUsername !== mappingUsername) {
      return c.json({ error: 'Username mismatch. This card is not for your Telegram account' }, 403);
    }

    mapping.status = 'claimed';
    mapping.realOwner = walletAddress;
    mapping.claimedAt = new Date().toISOString();

    await kv.set(`telegram_card:${tokenId}`, mapping);

    return c.json({
      success: true,
      mapping,
      message: 'Card claimed successfully. Transfer the NFT to complete the process.'
    });
  } catch (error) {
    console.log(`Error claiming Telegram card: ${error}`);
    return c.json({ error: 'Failed to claim Telegram card' }, 500);
  }
});

// Get Twitch access token from Privy
// Get saved OAuth token from database
app.post('/contacts/get-saved-token', async (c) => {
  try {
    const { privyUserId, platform = 'twitch' } = await c.req.json();
    
    if (!privyUserId) {
      return c.json({ error: 'Missing required field: privyUserId' }, 400);
    }

    const client = getSupabaseClient();
    
    // Get saved token from database
    const { data: tokenData, error } = await client
      .from('oauth_tokens')
      .select('*')
      .eq('user_id', privyUserId)
      .eq('platform', platform)
      .single();

    if (error || !tokenData) {
      return c.json({
        success: false,
        error: 'No saved token found',
        needsAuth: true
      });
    }

    // Check if token is expired
    if (tokenData.expires_at && new Date(tokenData.expires_at) < new Date()) {
      // Token expired, delete it
      await client
        .from('oauth_tokens')
        .delete()
        .eq('user_id', privyUserId)
        .eq('platform', platform);

      return c.json({
        success: false,
        error: 'Token expired',
        needsAuth: true
      });
    }

    // Validate token by making a test request to Twitch API
    if (platform === 'twitch') {
      const twitchClientId = Deno.env.get('VITE_TWITCH_CLIENT_ID');
      if (!twitchClientId) {
        return c.json({
          success: true,
          accessToken: tokenData.access_token,
          twitchUserId: null
        });
      }

      try {
        const validateResponse = await fetch('https://id.twitch.tv/oauth2/validate', {
          method: 'GET',
          headers: {
            'Authorization': `OAuth ${tokenData.access_token}`
          }
        });

        if (!validateResponse.ok) {
          // Token is invalid, delete it
          await client
            .from('oauth_tokens')
            .delete()
            .eq('user_id', privyUserId)
            .eq('platform', platform);

          return c.json({
            success: false,
            error: 'Token validation failed',
            needsAuth: true
          });
        }

        const validateData = await validateResponse.json();
        return c.json({
          success: true,
          accessToken: tokenData.access_token,
          twitchUserId: validateData.user_id || null
        });
      } catch (validateError) {
        console.error('Error validating token:', validateError);
        // Return token anyway, let the sync endpoint handle validation
        return c.json({
          success: true,
          accessToken: tokenData.access_token,
          twitchUserId: null
        });
      }
    }

    return c.json({
      success: true,
      accessToken: tokenData.access_token
    });
  } catch (error) {
    console.error(`Error getting saved token:`, error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ 
      error: 'Failed to get saved token',
      details: errorMessage 
    }, 500);
  }
});

// Save OAuth token to database
app.post('/contacts/save-token', async (c) => {
  try {
    const { privyUserId, platform, accessToken, expiresIn, scope } = await c.req.json();
    
    if (!privyUserId || !platform || !accessToken) {
      return c.json({ error: 'Missing required fields: privyUserId, platform, accessToken' }, 400);
    }

    const client = getSupabaseClient();
    
    // Calculate expires_at if expiresIn is provided (in seconds)
    let expiresAt: string | null = null;
    if (expiresIn) {
      expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();
    }

    const { error } = await client
      .from('oauth_tokens')
      .upsert({
        user_id: privyUserId,
        platform: platform,
        access_token: accessToken,
        expires_at: expiresAt,
        scope: scope || null,
        updated_at: new Date().toISOString()
      }, {
        onConflict: 'user_id,platform'
      });

    if (error) {
      console.error('Error saving token:', error);
      return c.json({ error: 'Failed to save token', details: error.message }, 500);
    }

    return c.json({ success: true });
  } catch (error) {
    console.error(`Error saving token:`, error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ 
      error: 'Failed to save token',
      details: errorMessage 
    }, 500);
  }
});

app.post('/contacts/get-twitch-token', async (c) => {
  try {
    const { privyUserId } = await c.req.json();
    
    if (!privyUserId) {
      return c.json({ error: 'Missing required field: privyUserId' }, 400);
    }

    const privyAppId = Deno.env.get('PRIVY_APP_ID');
    const privyAppSecret = Deno.env.get('PRIVY_APP_SECRET') || Deno.env.get('PRIVY_API_KEY');
    
    console.log('Privy credentials check:', {
      hasAppId: !!privyAppId,
      hasAppSecret: !!privyAppSecret,
      appIdLength: privyAppId?.length || 0,
      secretLength: privyAppSecret?.length || 0
    });
    
    if (!privyAppId || !privyAppSecret) {
      return c.json({ 
        error: 'Privy credentials not configured',
        details: 'Please set PRIVY_APP_ID and PRIVY_APP_SECRET (or PRIVY_API_KEY) in Edge Function secrets',
        found: {
          PRIVY_APP_ID: !!privyAppId,
          PRIVY_APP_SECRET: !!Deno.env.get('PRIVY_APP_SECRET'),
          PRIVY_API_KEY: !!Deno.env.get('PRIVY_API_KEY')
        }
      }, 500);
    }

    // Extract user ID from did:privy: format if needed
    let userId = privyUserId;
    if (privyUserId.startsWith('did:privy:')) {
      userId = privyUserId.replace('did:privy:', '');
    }

    console.log(`Fetching linked accounts for Privy user: ${userId}, App ID: ${privyAppId}`);

    // Privy API uses Basic Auth with App ID and App Secret
    // Also requires privy-app-id header
    const basicAuth = btoa(`${privyAppId}:${privyAppSecret}`);

    // Try the correct Privy API endpoint with Basic Auth and privy-app-id header
    const response = await fetch(`https://auth.privy.io/api/v1/apps/${privyAppId}/users/${userId}/linked_accounts`, {
      method: 'GET',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'privy-app-id': privyAppId,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Privy API error: ${response.status}`, errorText.substring(0, 500));
      
      // Try alternative endpoint format with Basic Auth and privy-app-id header
      const altResponse = await fetch(`https://auth.privy.io/api/v1/users/${userId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Basic ${basicAuth}`,
          'privy-app-id': privyAppId,
          'Content-Type': 'application/json',
        },
      });

      if (!altResponse.ok) {
        const altErrorText = await altResponse.text();
        throw new Error(`Privy API error: ${response.status}. Tried both endpoints. Last error: ${altErrorText.substring(0, 200)}`);
      }

      const altData = await altResponse.json();
      console.log('Alternative endpoint response (full):', JSON.stringify(altData, null, 2));
      
      // Try to find Twitch in linked accounts
      // Privy uses "linked_accounts" (snake_case) not "linkedAccounts"
      let linkedAccounts = [];
      if (Array.isArray(altData.linked_accounts)) {
        linkedAccounts = altData.linked_accounts;
      } else if (Array.isArray(altData.linkedAccounts)) {
        linkedAccounts = altData.linkedAccounts;
      } else if (Array.isArray(altData.accounts)) {
        linkedAccounts = altData.accounts;
      } else if (Array.isArray(altData)) {
        linkedAccounts = altData;
      } else if (altData.linked_accounts) {
        linkedAccounts = Array.isArray(altData.linked_accounts) ? altData.linked_accounts : [altData.linked_accounts];
      } else if (altData.linkedAccounts) {
        linkedAccounts = Array.isArray(altData.linkedAccounts) ? altData.linkedAccounts : [altData.linkedAccounts];
      }
      
      console.log('Alternative endpoint - Found accounts:', linkedAccounts.length);
      console.log('Alternative endpoint - Account details:', linkedAccounts.map((a: any) => ({
        type: a.type,
        provider: a.provider,
        providerType: a.providerType,
        subject: a.subject,
        id: a.id,
        username: a.username
      })));
      
      // Privy uses "twitch_oauth" as type, not just "twitch"
      const twitchLinked = linkedAccounts.find((account: any) => {
        const type = (account.type || '').toLowerCase();
        const provider = (account.provider || '').toLowerCase();
        const providerType = (account.providerType || '').toLowerCase();
        return type === 'twitch' || type === 'twitch_oauth' || 
               provider === 'twitch' || provider === 'twitch_oauth' ||
               providerType === 'twitch' || providerType === 'twitch_oauth';
      });

      if (!twitchLinked) {
        return c.json({ 
          error: 'Twitch account not linked to this Privy user',
          debug: {
            totalAccounts: linkedAccounts.length,
            accountTypes: linkedAccounts.map((a: any) => a.type || a.provider || 'unknown'),
            userId: userId,
            fullResponse: altData
          }
        }, 404);
      }

      console.log('Alternative endpoint - Twitch account found:', {
        type: twitchLinked.type,
        subject: twitchLinked.subject,
        username: twitchLinked.username,
        hasOAuthToken: !!(twitchLinked.oauthToken || twitchLinked.accessToken),
        allKeys: Object.keys(twitchLinked)
      });

      if (!twitchLinked.oauthToken && !twitchLinked.accessToken) {
        // Privy doesn't expose OAuth tokens via API for security
        return c.json({ 
          success: false,
          error: 'Twitch OAuth token not available through Privy API',
          message: 'Privy does not provide OAuth tokens through their API for security reasons.',
          twitchUserId: twitchLinked.subject || twitchLinked.id,
          twitchUsername: twitchLinked.username,
          suggestion: 'Use direct Twitch OAuth authorization flow'
        });
      }

      return c.json({
        success: true,
        accessToken: twitchLinked.oauthToken || twitchLinked.accessToken,
        twitchUserId: twitchLinked.subject || twitchLinked.id || twitchLinked.userId,
      });
    }

    const data = await response.json();
    console.log('Privy API response (full):', JSON.stringify(data, null, 2));
    
    // Handle array or object response
    // Privy uses "linked_accounts" (snake_case) not "linkedAccounts"
    let accounts = [];
    if (Array.isArray(data)) {
      accounts = data;
    } else if (data.linked_accounts && Array.isArray(data.linked_accounts)) {
      accounts = data.linked_accounts;
    } else if (data.linkedAccounts && Array.isArray(data.linkedAccounts)) {
      accounts = data.linkedAccounts;
    } else if (data.accounts && Array.isArray(data.accounts)) {
      accounts = data.accounts;
    } else if (data.data && Array.isArray(data.data)) {
      accounts = data.data;
    }
    
    console.log('Found accounts:', accounts.length);
    console.log('Account types:', accounts.map((a: any) => ({
      type: a.type,
      provider: a.provider,
      providerType: a.providerType,
      subject: a.subject,
      id: a.id,
      username: a.username
    })));
    
    // Privy uses "twitch_oauth" as type, not just "twitch"
    const twitchLinked = accounts.find((account: any) => {
      const type = (account.type || '').toLowerCase();
      const provider = (account.provider || '').toLowerCase();
      const providerType = (account.providerType || '').toLowerCase();
      return type === 'twitch' || type === 'twitch_oauth' || 
             provider === 'twitch' || provider === 'twitch_oauth' ||
             providerType === 'twitch' || providerType === 'twitch_oauth';
    });

    if (!twitchLinked) {
      return c.json({ 
        error: 'Twitch account not linked to this Privy user',
        debug: {
          totalAccounts: accounts.length,
          accountTypes: accounts.map((a: any) => a.type || a.provider || 'unknown'),
          fullResponse: data
        }
      }, 404);
    }

    // Privy does not provide OAuth tokens through API for security reasons
    // We need to use an alternative approach
    console.log('Twitch account found, but checking for OAuth token...');
    console.log('Twitch account details:', {
      type: twitchLinked.type,
      subject: twitchLinked.subject,
      username: twitchLinked.username,
      hasOAuthToken: !!(twitchLinked.oauthToken || twitchLinked.accessToken),
      allKeys: Object.keys(twitchLinked)
    });

    if (!twitchLinked.oauthToken && !twitchLinked.accessToken) {
      // Privy doesn't expose OAuth tokens via API for security
      // Return Twitch user ID so client can request token refresh or use alternative method
      return c.json({ 
        success: false,
        error: 'Twitch OAuth token not available through Privy API',
        message: 'Privy does not provide OAuth tokens through their API for security reasons.',
        twitchUserId: twitchLinked.subject || twitchLinked.id,
        twitchUsername: twitchLinked.username,
        suggestion: 'Use direct Twitch OAuth authorization flow'
      });
    }

    return c.json({
      success: true,
      accessToken: twitchLinked.oauthToken || twitchLinked.accessToken,
      twitchUserId: twitchLinked.subject || twitchLinked.id || twitchLinked.userId,
    });
  } catch (error) {
    console.error(`Error getting Twitch token:`, error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ 
      error: 'Failed to get Twitch access token',
      details: errorMessage 
    }, 500);
  }
});

app.post('/contacts/get-twitter-token', async (c) => {
  try {
    const { privyUserId } = await c.req.json();
    
    if (!privyUserId) {
      return c.json({ error: 'Missing required field: privyUserId' }, 400);
    }

    const privyAppId = Deno.env.get('PRIVY_APP_ID');
    const privyAppSecret = Deno.env.get('PRIVY_APP_SECRET') || Deno.env.get('PRIVY_API_KEY');
    
    if (!privyAppId || !privyAppSecret) {
      return c.json({ 
        error: 'Privy credentials not configured',
        details: 'Please set PRIVY_APP_ID and PRIVY_APP_SECRET (or PRIVY_API_KEY) in Edge Function secrets',
      }, 500);
    }

    let userId = privyUserId;
    if (privyUserId.startsWith('did:privy:')) {
      userId = privyUserId.replace('did:privy:', '');
    }

    const basicAuth = btoa(`${privyAppId}:${privyAppSecret}`);

    const response = await fetch(`https://auth.privy.io/api/v1/apps/${privyAppId}/users/${userId}/linked_accounts`, {
      method: 'GET',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'privy-app-id': privyAppId,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      const altResponse = await fetch(`https://auth.privy.io/api/v1/users/${userId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Basic ${basicAuth}`,
          'privy-app-id': privyAppId,
          'Content-Type': 'application/json',
        },
      });

      if (!altResponse.ok) {
        throw new Error(`Privy API error: ${response.status}`);
      }

      const altData = await altResponse.json();
      
      let linkedAccounts = [];
      if (Array.isArray(altData.linked_accounts)) {
        linkedAccounts = altData.linked_accounts;
      } else if (Array.isArray(altData.linkedAccounts)) {
        linkedAccounts = altData.linkedAccounts;
      } else if (Array.isArray(altData.accounts)) {
        linkedAccounts = altData.accounts;
      }
      
      const twitterLinked = linkedAccounts.find((account: any) => {
        const type = (account.type || '').toLowerCase();
        const provider = (account.provider || '').toLowerCase();
        return type === 'twitter' || type === 'twitter_oauth' || 
               provider === 'twitter' || provider === 'twitter_oauth';
      });

      if (!twitterLinked) {
        return c.json({ 
          error: 'Twitter account not linked to this Privy user',
        }, 404);
      }

      if (!twitterLinked.oauthToken && !twitterLinked.accessToken) {
        return c.json({ 
          success: false,
          error: 'Twitter OAuth token not available through Privy API',
          message: 'Privy does not provide OAuth tokens through their API for security reasons.',
          twitterUserId: twitterLinked.subject || twitterLinked.id,
          suggestion: 'Use direct Twitter OAuth authorization flow'
        });
      }

      return c.json({
        success: true,
        accessToken: twitterLinked.oauthToken || twitterLinked.accessToken,
        twitterUserId: twitterLinked.subject || twitterLinked.id,
      });
    }

    const data = await response.json();
    
    let accounts = [];
    if (Array.isArray(data)) {
      accounts = data;
    } else if (data.linked_accounts && Array.isArray(data.linked_accounts)) {
      accounts = data.linked_accounts;
    } else if (data.linkedAccounts && Array.isArray(data.linkedAccounts)) {
      accounts = data.linkedAccounts;
    } else if (data.accounts && Array.isArray(data.accounts)) {
      accounts = data.accounts;
    }
    
    const twitterLinked = accounts.find((account: any) => {
      const type = (account.type || '').toLowerCase();
      const provider = (account.provider || '').toLowerCase();
      return type === 'twitter' || type === 'twitter_oauth' || 
             provider === 'twitter' || provider === 'twitter_oauth';
    });

    if (!twitterLinked) {
      return c.json({ 
        error: 'Twitter account not linked to this Privy user',
      }, 404);
    }

    if (!twitterLinked.oauthToken && !twitterLinked.accessToken) {
      return c.json({ 
        success: false,
        error: 'Twitter OAuth token not available through Privy API',
        message: 'Privy does not provide OAuth tokens through their API for security reasons.',
        twitterUserId: twitterLinked.subject || twitterLinked.id,
        suggestion: 'Use direct Twitter OAuth authorization flow'
      });
    }

    return c.json({
      success: true,
      accessToken: twitterLinked.oauthToken || twitterLinked.accessToken,
      twitterUserId: twitterLinked.subject || twitterLinked.id,
    });
  } catch (error) {
    console.error(`Error getting Twitter token:`, error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ 
      error: 'Failed to get Twitter access token',
      details: errorMessage 
    }, 500);
  }
});

app.post('/contacts/twitter-exchange-code', async (c) => {
  try {
    const { code, redirectUri, codeVerifier } = await c.req.json();
    
    console.log('[TWITTER EXCHANGE] Received request data:', {
      hasCode: !!code,
      codeLength: code?.length || 0,
      codePreview: code ? `${code.substring(0, 20)}...` : 'none',
      redirectUri: redirectUri,
      hasCodeVerifier: !!codeVerifier,
      codeVerifierLength: codeVerifier?.length || 0,
    });
    
    if (!code || !redirectUri) {
      return c.json({ error: 'Missing required fields: code, redirectUri' }, 400);
    }

    const twitterClientId = Deno.env.get('TWITTER_CLIENT_ID') || Deno.env.get('VITE_TWITTER_CLIENT_ID');
    const twitterClientSecret = Deno.env.get('TWITTER_CLIENT_SECRET') || Deno.env.get('VITE_TWITTER_CLIENT_SECRET');
    
    if (!twitterClientId || !twitterClientSecret) {
      return c.json({ 
        error: 'Twitter credentials not configured',
        details: 'Please set TWITTER_CLIENT_ID and TWITTER_CLIENT_SECRET in Edge Function secrets',
      }, 500);
    }

    console.log('[TWITTER EXCHANGE] Environment check:', {
      hasTWITTER_CLIENT_ID: !!Deno.env.get('TWITTER_CLIENT_ID'),
      hasVITE_TWITTER_CLIENT_ID: !!Deno.env.get('VITE_TWITTER_CLIENT_ID'),
      hasTWITTER_CLIENT_SECRET: !!Deno.env.get('TWITTER_CLIENT_SECRET'),
      hasVITE_TWITTER_CLIENT_SECRET: !!Deno.env.get('VITE_TWITTER_CLIENT_SECRET'),
      clientIdLength: twitterClientId?.length || 0,
      clientSecretLength: twitterClientSecret?.length || 0,
      clientIdFull: twitterClientId || 'none',
      clientIdRaw: Deno.env.get('TWITTER_CLIENT_ID') || Deno.env.get('VITE_TWITTER_CLIENT_ID') || 'none',
    });
    
    console.log('[CLIENT_ID_CHECK] Full client_id being used:', twitterClientId || 'NOT_SET');
    console.log('[CLIENT_ID_CHECK] Expected client_id from client:', 'T3pFZGVLRHFxNVdiNVVQRW1iWlY6MTpjaQ');
    console.log('[CLIENT_ID_CHECK] Client IDs match:', twitterClientId === 'T3pFZGVLRHFxNVdiNVVQRW1iWlY6MTpjaQ');

    const tokenUrl = 'https://api.twitter.com/2/oauth2/token';
    const params = new URLSearchParams();
    params.append('code', code);
    params.append('grant_type', 'authorization_code');
    params.append('client_id', twitterClientId);
    params.append('redirect_uri', redirectUri);
    if (codeVerifier) {
      params.append('code_verifier', codeVerifier);
    }
    
    console.log('[TWITTER EXCHANGE] Token request params:', {
      tokenUrl: tokenUrl,
      redirectUri: redirectUri,
      hasCodeVerifier: !!codeVerifier,
      codeLength: code.length,
      paramsKeys: Array.from(params.keys()),
      bodyLength: params.toString().length,
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${btoa(`${twitterClientId}:${twitterClientSecret}`)}`,
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Twitter token exchange error: ${response.status} ${response.statusText}. ${errorText}`);
    }

    const tokenData = await response.json();

    return c.json({
      success: true,
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expiresIn: tokenData.expires_in,
    });
  } catch (error) {
    console.error(`Error exchanging Twitter code:`, error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ 
      error: 'Failed to exchange Twitter authorization code',
      details: errorMessage 
    }, 500);
  }
});

// Sync contacts from social media platforms
app.post('/contacts/sync', async (c) => {
  try {
    const requestData = await c.req.json();
    // userId -  Twitch/Twitter user ID (numeric) for API
    // walletAddress -  wallet address for saving to DB as user_id
    const { platform, userId, accessToken, clientId, privyUserId, walletAddress } = requestData;
    
    if (!platform || !userId) {
      return c.json({ error: 'Missing required fields: platform, userId' }, 400);
    }

    const client = getSupabaseClient();

    if (platform === 'twitch') {
      if (!accessToken || !clientId) {
        return c.json({ error: 'Missing required fields for Twitch: accessToken, clientId' }, 400);
      }

      //   wallet address for saving to DB (if provided), otherwise use userId
      // This is needed for compatibility with old data
      const dbUserId = walletAddress ? walletAddress.toLowerCase().trim() : userId;
      console.log('[TWITCH SYNC] Using userId for API:', userId, 'dbUserId for DB:', dbUserId);

      const TWITCH_API_BASE_URL = 'https://api.twitch.tv/helix';
      const allContacts: any[] = [];
      let cursor: string | undefined = undefined;

      do {
        const url = new URL(`${TWITCH_API_BASE_URL}/channels/followed`);
        // For Twitch API use numeric Twitch user ID
        url.searchParams.set('user_id', userId);
        if (cursor) {
          url.searchParams.set('after', cursor);
        }

        const response = await fetch(url.toString(), {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Client-Id': clientId,
          },
        });

        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(
            `Twitch API error: ${response.status} ${response.statusText}. ${errorText}`
          );
        }

        const data = await response.json();

        if (data.data && Array.isArray(data.data)) {
          allContacts.push(...data.data);
        }

        cursor = data.pagination?.cursor;
      } while (cursor);

      if (allContacts.length > 0) {
        // Save to DB with wallet address as user_id (for compatibility with personal_contacts)
        const records = allContacts.map((contact) => ({
          user_id: dbUserId, // Use wallet address for DB
          broadcaster_id: contact.broadcaster_id,
          broadcaster_login: contact.broadcaster_login,
          broadcaster_name: contact.broadcaster_name,
          followed_at: contact.followed_at ? new Date(contact.followed_at).toISOString() : null,
          synced_at: new Date().toISOString(),
        }));

        console.log('[TWITCH SYNC] Saving', records.length, 'contacts with user_id:', dbUserId);

        const { error: upsertError } = await client
          .from('twitch_followed')
          .upsert(records, {
            onConflict: 'user_id,broadcaster_id',
            ignoreDuplicates: false,
          });

        if (upsertError) {
          console.error('Error saving Twitch contacts:', upsertError);
          throw new Error(`Failed to save contacts: ${upsertError.message}`);
        }
      }

      // Save the access token to database for future use
      // Twitch tokens typically don't expire, but we'll save it anyway
      if (privyUserId) {
        try {
          await client
            .from('oauth_tokens')
            .upsert({
              user_id: privyUserId,
              platform: 'twitch',
              access_token: accessToken,
              expires_at: null, // Twitch tokens don't expire unless revoked
              scope: 'user:read:follows',
              updated_at: new Date().toISOString()
            }, {
              onConflict: 'user_id,platform'
            });
        } catch (tokenError) {
          console.error('Error saving token (non-critical):', tokenError);
          // Don't fail the sync if token saving fails
        }
      }

      return c.json({
        success: true,
        platform: 'twitch',
        contactsCount: allContacts.length,
        contacts: allContacts.map((c) => ({
          broadcaster_id: c.broadcaster_id,
          broadcaster_login: c.broadcaster_login,
          broadcaster_name: c.broadcaster_name,
          followed_at: c.followed_at,
        })),
      });
                      } else if (platform === 'twitter') {
        if (!accessToken) {
          return c.json({ error: 'Missing required fields for Twitter: accessToken' }, 400);
        }

        const TWITTER_API_BASE_URL = 'https://api.twitter.com/2';
        
        // Log token info for debugging (without exposing full token)
        console.log('[TWITTER SYNC] Token info:', {
          hasToken: !!accessToken,
          tokenLength: accessToken?.length || 0,
          tokenPrefix: accessToken ? `${accessToken.substring(0, 20)}...` : 'none',
          userIdParameter: userId,
        });
        
        // Check if userId looks like a Twitter user ID (numeric string, typically 15-20 digits)
        const isTwitterUserId = /^\d+$/.test(userId);
        let twitterUserId: string | null = null;
        
        if (isTwitterUserId) {
          // If userId is already a Twitter user ID, use it directly
          // This avoids the need for /users/me which requires specific scopes
          console.log('[TWITTER SYNC] Using userId parameter as Twitter user ID:', userId);
          twitterUserId = userId;
        } else {
          // Try to get user ID from /users/me endpoint as fallback
          // Note: This requires scopes: tweet.read users.read
          console.log('[TWITTER SYNC] Attempting to get user info from /users/me...');
          try {
            const meResponse = await fetch(`${TWITTER_API_BASE_URL}/users/me?user.fields=id,username,name`, {
              method: 'GET',
              headers: {
                'Authorization': `Bearer ${accessToken}`,
              },
            });

            if (meResponse.ok) {
              const meData = await meResponse.json();
              twitterUserId = meData.data?.id;
              console.log('[TWITTER SYNC] Successfully got user ID from /users/me:', twitterUserId);
            } else {
              const errorText = await meResponse.text();
              console.warn('[TWITTER SYNC] /users/me failed:', meResponse.status, errorText);
              console.warn('[TWITTER SYNC] This might be due to missing scopes (requires: tweet.read users.read)');
              // Fallback to userId parameter if available
              if (userId) {
                console.log('[TWITTER SYNC] Falling back to using userId parameter:', userId);
                twitterUserId = userId;
              } else {
                throw new Error(
                  `Cannot determine Twitter user ID. /users/me returned ${meResponse.status}: ${errorText}. ` +
                  `Please ensure your token has scopes: tweet.read users.read follows.read, or provide userId as Twitter user ID.`
                );
              }
            }
          } catch (meError) {
            console.error('[TWITTER SYNC] Error calling /users/me:', meError);
            // Fallback to userId parameter if available
            if (userId) {
              console.log('[TWITTER SYNC] Falling back to using userId parameter due to error:', userId);
              twitterUserId = userId;
            } else {
              throw new Error(`Failed to get Twitter user ID: ${meError instanceof Error ? meError.message : 'Unknown error'}`);
            }
          }
        }

        if (!twitterUserId) {
          throw new Error('Could not determine Twitter user ID. Please provide userId as Twitter user ID (numeric string).');
        }

        console.log('[TWITTER SYNC] Using Twitter user ID for following request:', twitterUserId);

        const allContacts: any[] = [];
        let paginationToken: string | undefined = undefined;

        do {
          // Use the Twitter user ID from /users/me, not the userId parameter
          const url = new URL(`${TWITTER_API_BASE_URL}/users/${twitterUserId}/following`);
          url.searchParams.set('max_results', '1000');
          if (paginationToken) {
            url.searchParams.set('pagination_token', paginationToken);
          }

          console.log('[TWITTER SYNC] Fetching following list:', url.toString());

          const response = await fetch(url.toString(), {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${accessToken}`,
            },
          });

          if (!response.ok) {
            const errorText = await response.text();
            console.error('[TWITTER SYNC] Failed to get following list:', response.status, errorText);
            throw new Error(
              `Twitter API error: ${response.status} ${response.statusText}. ${errorText}`
            );
          }

          const data = await response.json();

        if (data.data && Array.isArray(data.data)) {
          allContacts.push(...data.data);
        }

        paginationToken = data.meta?.next_token;
      } while (paginationToken);

                if (allContacts.length > 0) {
          console.log('[TWITTER SYNC] Saving', allContacts.length, 'contacts to database');
          // Use wallet address for saving to DB (if provided), otherwise use userId
          // This is needed for compatibility with old data
          const dbUserId = walletAddress ? walletAddress.toLowerCase().trim() : userId;
          console.log('[TWITTER SYNC] Using twitterUserId for API:', twitterUserId, 'dbUserId for DB:', dbUserId);
          
          const records = allContacts.map((contact) => ({
            user_id: dbUserId, // Use wallet address for DB
            twitter_user_id: contact.id,
            username: contact.username,
            display_name: contact.name,
            followed_at: new Date().toISOString(),
            synced_at: new Date().toISOString(),
          }));

        const { error: upsertError } = await client
          .from('twitter_followed')
          .upsert(records, {
            onConflict: 'user_id,twitter_user_id',
            ignoreDuplicates: false,
          });

        if (upsertError) {
          console.error('Error saving Twitter contacts:', upsertError);
          throw new Error(`Failed to save contacts: ${upsertError.message}`);
        }
      }

      if (privyUserId) {
        try {
          await client
            .from('oauth_tokens')
            .upsert({
              user_id: privyUserId,
              platform: 'twitter',
              access_token: accessToken,
              expires_at: null,
              scope: 'users.read follows.read',
              updated_at: new Date().toISOString()
            }, {
              onConflict: 'user_id,platform'
            });
        } catch (tokenError) {
          console.error('Error saving token (non-critical):', tokenError);
        }
      }

      return c.json({
        success: true,
        platform: 'twitter',
        contactsCount: allContacts.length,
        contacts: allContacts.map((c) => ({
          twitter_user_id: c.id,
          username: c.username,
          display_name: c.name,
          followed_at: new Date().toISOString(),
        })),
      });
    } else if (platform === 'telegram') {
      const telegramUserIdRaw = requestData.telegramUserId ?? userId;
      const telegramUserId = normalizeTelegramId(telegramUserIdRaw);
      const dbUserId = walletAddress ? walletAddress.toLowerCase().trim() : telegramUserId;

      if (!telegramUserId) {
        return c.json({ error: 'Missing required field: telegramUserId' }, 400);
      }

      if (!dbUserId) {
        return c.json({ error: 'Unable to determine database user_id for Telegram sync' }, 400);
      }

      const client = getSupabaseClient();

      let contactsPayload: any[] | null = Array.isArray(requestData.contacts) ? requestData.contacts : null;

      if (!contactsPayload) {
        const serviceUrl = Deno.env.get('TELEGRAM_CONTACTS_SERVICE_URL');
        const serviceApiKey = Deno.env.get('TELEGRAM_CONTACTS_SERVICE_API_KEY');

        if (!serviceUrl) {
          return c.json({
            error: 'Telegram contacts service not configured',
            details: 'Set TELEGRAM_CONTACTS_SERVICE_URL or provide contacts array in request body',
          }, 500);
        }

        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
        };

        if (serviceApiKey) {
          headers['Authorization'] = `Bearer ${serviceApiKey}`;
        }

        const servicePayload = {
          telegramUserId,
          privyUserId: normalizePrivyUserId(privyUserId),
          walletAddress: dbUserId,
          username: requestData.telegramUsername ?? requestData.username ?? null,
          authData: requestData.authData ?? requestData.telegramAuthData ?? null,
          metadata: requestData.telegramProfile ?? requestData.profile ?? null,
        };

        try {
          const serviceResponse = await fetch(serviceUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(servicePayload),
          });

          if (!serviceResponse.ok) {
            const errorText = await serviceResponse.text();
            throw new Error(`Telegram contacts service error: ${serviceResponse.status} ${serviceResponse.statusText}. ${errorText}`);
          }

          const serviceData = await serviceResponse.json();
          if (Array.isArray(serviceData?.contacts)) {
            contactsPayload = serviceData.contacts;
          } else if (Array.isArray(serviceData)) {
            contactsPayload = serviceData;
          } else {
            contactsPayload = [];
          }
        } catch (error) {
          console.error('[TELEGRAM SYNC] Failed to fetch contacts from service:', error);
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          return c.json({ error: 'Failed to fetch Telegram contacts', details: errorMessage }, 500);
        }
      }

      const uniqueContacts = new Map<string, any>();
      const nowIso = new Date().toISOString();

      (contactsPayload || []).forEach((contactRaw) => {
        const contactId = normalizeTelegramId(
          contactRaw?.telegram_user_id ??
          contactRaw?.telegramUserId ??
          contactRaw?.id ??
          contactRaw?.user_id ??
          contactRaw?.userId ??
          contactRaw?.chat_id ??
          contactRaw?.chatId
        );

        if (!contactId) {
          return;
        }

        if (uniqueContacts.has(contactId)) {
          return;
        }

        const firstName = contactRaw?.first_name ?? contactRaw?.firstName ?? null;
        const lastName = contactRaw?.last_name ?? contactRaw?.lastName ?? null;
        const username = contactRaw?.username ?? contactRaw?.handle ?? contactRaw?.telegram_username ?? null;
        const displayNameSource = contactRaw?.display_name ?? contactRaw?.displayName ?? null;
        const displayNameFallback = [firstName, lastName].filter(Boolean).join(' ').trim();
        const displayName = (displayNameSource && String(displayNameSource).trim().length > 0)
          ? String(displayNameSource).trim()
          : (displayNameFallback.length > 0 ? displayNameFallback : (username || contactId));

        uniqueContacts.set(contactId, {
          telegram_user_id: contactId,
          username,
          first_name: firstName,
          last_name: lastName,
          display_name: displayName,
          phone_number: contactRaw?.phone_number ?? contactRaw?.phoneNumber ?? null,
          avatar_url: contactRaw?.avatar_url ?? contactRaw?.avatarUrl ?? contactRaw?.photo_url ?? contactRaw?.photoUrl ?? null,
          is_bot: typeof contactRaw?.is_bot === 'boolean' ? contactRaw.is_bot : (typeof contactRaw?.isBot === 'boolean' ? contactRaw.isBot : null),
          language_code: contactRaw?.language_code ?? contactRaw?.languageCode ?? null,
          synced_at: contactRaw?.synced_at ?? contactRaw?.syncedAt ?? nowIso,
        });
      });

      const contactsArray = Array.from(uniqueContacts.values());

      if (contactsArray.length > 0) {
        const records = contactsArray.map((contact) => ({
          user_id: dbUserId,
          telegram_user_id: contact.telegram_user_id,
          username: contact.username,
          first_name: contact.first_name,
          last_name: contact.last_name,
          display_name: contact.display_name,
          phone_number: contact.phone_number,
          avatar_url: contact.avatar_url,
          is_bot: contact.is_bot,
          language_code: contact.language_code,
          synced_at: contact.synced_at ? new Date(contact.synced_at).toISOString() : nowIso,
          updated_at: nowIso,
        }));

        const { error: upsertError } = await client
          .from('telegram_contacts')
          .upsert(records, {
            onConflict: 'user_id,telegram_user_id',
            ignoreDuplicates: false,
          });

        if (upsertError) {
          console.error('Error saving Telegram contacts:', upsertError);
          throw new Error(`Failed to save Telegram contacts: ${upsertError.message}`);
        }
      }

      return c.json({
        success: true,
        platform: 'telegram',
        contactsCount: contactsArray.length,
        contacts: contactsArray,
      });
    } else {
      return c.json({ error: `Platform ${platform} is not yet supported` }, 400);
    }
  } catch (error) {
    console.error(`Error syncing contacts:`, error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ 
      error: 'Failed to sync contacts',
      details: errorMessage 
    }, 500);
  }
});

// Personal contacts endpoints (must be before /contacts/:platform to avoid route conflict)
// Save personal contact (bypasses RLS using service_role)
app.post('/contacts/personal', async (c) => {
  try {
    const { userId, name, wallet } = await c.req.json();
    
    if (!userId || !name || !wallet) {
      return c.json({ 
        error: 'Missing required fields',
        required: ['userId', 'name', 'wallet']
      }, 400);
    }

    const client = getSupabaseClient();
    
    const { data, error } = await client
      .from('personal_contacts')
      .upsert(
        {
          user_id: userId,
          name: name.trim(),
          wallet: wallet.trim(),
        },
        {
          onConflict: 'user_id,wallet',
          ignoreDuplicates: false,
        }
      )
      .select();

    if (error) {
      console.error('[PERSONAL CONTACT] Error saving:', error);
      return c.json({ 
        error: 'Failed to save personal contact',
        details: error.message 
      }, 500);
    }

    return c.json({
      success: true,
      data: data?.[0] || null,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[PERSONAL CONTACT] Unexpected error:', errorMessage);
    return c.json({ 
      error: 'Internal server error',
      details: errorMessage 
    }, 500);
  }
});

// Get personal contacts (bypasses RLS using service_role)
app.get('/contacts/personal', async (c) => {
  try {
    const userId = c.req.query('userId');
    
    console.log('[PERSONAL CONTACT GET] Request received:', { userId, path: c.req.path, method: c.req.method });
    
    if (!userId) {
      console.log('[PERSONAL CONTACT GET] Missing userId parameter');
      return c.json({ 
        error: 'Missing required parameter',
        required: ['userId']
      }, 400);
    }

    const client = getSupabaseClient();
    
    // Normalize userId to lowercase for consistent comparison
    const normalizedUserId = userId.toLowerCase().trim();
    console.log('[PERSONAL CONTACT GET] Querying with normalized userId:', normalizedUserId);
    
    const { data, error } = await client
      .from('personal_contacts')
      .select('*')
      .eq('user_id', normalizedUserId)
      .order('is_favorite', { ascending: false })
      .order('name', { ascending: true });

    if (error) {
      console.error('[PERSONAL CONTACT GET] Database error:', error);
      return c.json({ 
        error: 'Failed to fetch personal contacts',
        details: error.message 
      }, 500);
    }

    console.log('[PERSONAL CONTACT GET] Successfully fetched', data?.length || 0, 'contacts');
    
    return c.json({
      success: true,
      data: data || [],
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[PERSONAL CONTACT GET] Unexpected error:', errorMessage, error);
    return c.json({ 
      error: 'Internal server error',
      details: errorMessage 
    }, 500);
  }
});

// Delete personal contact
app.delete('/contacts/personal', async (c) => {
  try {
    const { userId, wallet } = await c.req.json();
    
    if (!userId || !wallet) {
      return c.json({ 
        error: 'Missing required fields',
        required: ['userId', 'wallet']
      }, 400);
    }

    const client = getSupabaseClient();
    
    const { error } = await client
      .from('personal_contacts')
      .delete()
      .eq('user_id', userId)
      .eq('wallet', wallet);

    if (error) {
      console.error('[PERSONAL CONTACT] Error deleting:', error);
      return c.json({ 
        error: 'Failed to delete personal contact',
        details: error.message 
      }, 500);
    }

    return c.json({
      success: true,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[PERSONAL CONTACT] Unexpected error:', errorMessage);
    return c.json({ 
      error: 'Internal server error',
      details: errorMessage 
    }, 500);
  }
});

// Toggle favorite status for personal contact
app.patch('/contacts/personal/favorite', async (c) => {
  try {
    const { userId, wallet, isFavorite } = await c.req.json();
    
    console.log('[PERSONAL CONTACT FAVORITE] Request received:', { userId, wallet, isFavorite });
    
    if (!userId || !wallet || typeof isFavorite !== 'boolean') {
      return c.json({ 
        error: 'Missing required fields',
        required: ['userId', 'wallet', 'isFavorite']
      }, 400);
    }

    const client = getSupabaseClient();
    
    // Find record by wallet (user_id is now wallet address)
    // Normalize wallet address for comparison
    const normalizedWallet = wallet.toLowerCase().trim();
    const normalizedUserId = userId.toLowerCase().trim();
    
    // Try to find by user_id (wallet address) and contact wallet
    // Since user_id is now wallet address, we search by user_id matching the contact's wallet owner
    let existingRecord = null;
    
    // First attempt: find by user_id (which should be the wallet address of the owner)
    // and the contact's wallet address
    const { data: recordsByUserAndWallet, error: selectError1 } = await client
      .from('personal_contacts')
      .select('id, user_id, wallet, is_favorite')
      .eq('user_id', normalizedUserId)
      .eq('wallet', normalizedWallet)
      .limit(1);

    if (recordsByUserAndWallet && recordsByUserAndWallet.length > 0) {
      existingRecord = recordsByUserAndWallet[0] as any;
      console.log('[PERSONAL CONTACT FAVORITE] Found record by userId and wallet:', existingRecord);
    } else {
      // Second attempt: find by wallet only (in case user_id was different before migration)
      console.log('[PERSONAL CONTACT FAVORITE] Record not found by userId and wallet, trying wallet only...');
      const { data: recordsByWallet, error: selectError2 } = await client
        .from('personal_contacts')
        .select('id, user_id, wallet, is_favorite')
        .ilike('wallet', normalizedWallet)
        .limit(1);

      if (recordsByWallet && recordsByWallet.length > 0) {
        existingRecord = recordsByWallet[0] as any;
        console.log('[PERSONAL CONTACT FAVORITE] Found record by wallet only:', existingRecord);
        console.log('[PERSONAL CONTACT FAVORITE] Note: user_id mismatch. DB:', existingRecord.user_id, 'Request:', normalizedUserId);
        
        // Update user_id to wallet address (migration from old system)
        if (existingRecord && existingRecord.user_id !== normalizedUserId) {
          console.log('[PERSONAL CONTACT FAVORITE] Migrating user_id from', existingRecord.user_id, 'to wallet address:', normalizedUserId);
          const { error: updateUserIdError } = await client
            .from('personal_contacts')
            .update({ user_id: normalizedUserId })
            .eq('id', existingRecord.id);
          
          if (updateUserIdError) {
            console.error('[PERSONAL CONTACT FAVORITE] Error updating user_id:', updateUserIdError);
          } else {
            existingRecord.user_id = normalizedUserId;
            console.log('[PERSONAL CONTACT FAVORITE] user_id migrated successfully to wallet address');
          }
        }
      } else {
        console.error('[PERSONAL CONTACT FAVORITE] Record not found by wallet either. Errors:', selectError1, selectError2);
        return c.json({ 
          error: 'Contact not found',
          details: `No contact found with wallet: ${wallet}. Searched with userId (wallet): ${userId} and wallet only.`
        }, 404);
      }
    }

    if (!existingRecord) {
      console.error('[PERSONAL CONTACT FAVORITE] Record not found for:', { userId, wallet });
      return c.json({ 
        error: 'Contact not found',
        details: 'No contact found with the provided userId and wallet'
      }, 404);
    }

    console.log('[PERSONAL CONTACT FAVORITE] Found record:', existingRecord);
    const currentFavorite = (existingRecord as any).is_favorite || false;
    console.log('[PERSONAL CONTACT FAVORITE] Current is_favorite:', currentFavorite, 'New value:', isFavorite);
    
    // Check if update is needed
    if (currentFavorite === isFavorite) {
      console.log('[PERSONAL CONTACT FAVORITE] Value already set, no update needed');
      return c.json({
        success: true,
        message: 'Value already set',
        data: existingRecord,
      });
    }
    
    // Update the record - explicitly set updated_at to ensure trigger fires
    // Use id for update to ensure we update the correct record
    const { data: updatedData, error: updateError } = await client
      .from('personal_contacts')
      .update({ 
        is_favorite: isFavorite,
        updated_at: new Date().toISOString() // Explicitly update timestamp
      })
      .eq('id', (existingRecord as any).id)
      .select();

    if (updateError) {
      console.error('[PERSONAL CONTACT FAVORITE] Error updating favorite:', updateError);
      return c.json({ 
        error: 'Failed to update favorite status',
        details: updateError.message 
      }, 500);
    }

    if (!updatedData || updatedData.length === 0) {
      console.error('[PERSONAL CONTACT FAVORITE] No rows updated');
      return c.json({ 
        error: 'No rows updated',
        details: 'The update query did not affect any rows'
      }, 500);
    }

    console.log('[PERSONAL CONTACT FAVORITE] Update successful:', updatedData);

    return c.json({
      success: true,
      data: updatedData[0],
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[PERSONAL CONTACT FAVORITE] Unexpected error:', errorMessage);
    return c.json({ 
      error: 'Internal server error',
      details: errorMessage 
    }, 500);
  }
});

// Get synced contacts
app.get('/contacts/:platform', async (c) => {
  try {
    const platform = c.req.param('platform');
    const userId = c.req.query('userId');
    
    if (!userId) {
      return c.json({ error: 'Missing userId query parameter' }, 400);
    }

    const client = getSupabaseClient();

    if (platform === 'twitch') {
      const { data, error } = await client
        .from('twitch_followed')
        .select('*')
        .eq('user_id', userId)
        .order('is_favorite', { ascending: false })
        .order('broadcaster_name', { ascending: true });

      if (error) {
        throw new Error(`Failed to fetch contacts: ${error.message}`);
      }

      return c.json({
        success: true,
        platform: 'twitch',
        contacts: (data || []).map((row) => ({
          broadcaster_id: row.broadcaster_id,
          broadcaster_login: row.broadcaster_login,
          broadcaster_name: row.broadcaster_name,
          followed_at: row.followed_at,
          is_favorite: row.is_favorite || false,
        })),
      });
    } else if (platform === 'twitter') {
      const { data, error } = await client
        .from('twitter_followed')
        .select('*')
        .eq('user_id', userId)
        .order('is_favorite', { ascending: false })
        .order('display_name', { ascending: true });

      if (error) {
        throw new Error(`Failed to fetch contacts: ${error.message}`);
      }

      return c.json({
        success: true,
        platform: 'twitter',
        contacts: (data || []).map((row) => ({
          twitter_user_id: row.twitter_user_id,
          username: row.username,
          display_name: row.display_name,
          followed_at: row.followed_at,
          is_favorite: row.is_favorite || false,
        })),
      });
    } else if (platform === 'telegram') {
      const { data, error } = await client
        .from('telegram_contacts')
        .select('*')
        .eq('user_id', userId)
        .order('is_favorite', { ascending: false })
        .order('display_name', { ascending: true });

      if (error) {
        throw new Error(`Failed to fetch contacts: ${error.message}`);
      }

      return c.json({
        success: true,
        platform: 'telegram',
        contacts: (data || []).map((row) => ({
          telegram_user_id: row.telegram_user_id,
          username: row.username,
          first_name: row.first_name,
          last_name: row.last_name,
          display_name: row.display_name,
          phone_number: row.phone_number,
          avatar_url: row.avatar_url,
          is_bot: row.is_bot,
          language_code: row.language_code,
          synced_at: row.synced_at,
          is_favorite: row.is_favorite || false,
        })),
      });
    } else {
      return c.json({ error: `Platform ${platform} is not yet supported` }, 400);
    }
  } catch (error) {
    console.error(`Error fetching contacts:`, error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ 
      error: 'Failed to fetch contacts',
      details: errorMessage 
    }, 500);
  }
});

// Handler for all other routes (404)
app.notFound((c) => {
  console.log('Route not found:', c.req.method, c.req.path);
  return c.json({ 
    error: 'Route not found',
    method: c.req.method,
    path: c.req.path,
    availableRoutes: [
      'GET /',
      'POST /gift-cards/twitter/create',
      'GET /gift-cards/twitter/:username',
      'GET /gift-cards/twitter/by-token/:tokenId',
      'POST /gift-cards/twitter/:tokenId/claim',
      'POST /gift-cards/twitch/create',
      'GET /gift-cards/twitch/:username',
      'GET /gift-cards/twitch/by-token/:tokenId',
      'POST /gift-cards/twitch/:tokenId/claim',
      'POST /gift-cards/telegram/create',
      'GET /gift-cards/telegram/:username',
      'GET /gift-cards/telegram/by-token/:tokenId',
      'POST /gift-cards/telegram/:tokenId/claim',
      'POST /contacts/get-twitch-token',
      'POST /contacts/get-twitter-token',
      'POST /contacts/twitter-exchange-code',
      'POST /contacts/sync',
      'POST /contacts/personal',
      'GET /contacts/personal',
      'DELETE /contacts/personal',
      'PATCH /contacts/personal/favorite',
      'PATCH /contacts/social/favorite',
      'GET /contacts/:platform',
      'POST /wallets/create',
      'GET /wallets',
      'POST /wallets/link-telegram'
    ]
  }, 404);
});

// Developer-Controlled Wallet endpoints
// Create a Developer-Controlled Wallet for a user
app.post('/wallets/create', async (c) => {
  try {
    const { userId, blockchain = 'ARC-TESTNET', accountType = 'EOA' } = await c.req.json();
    
    if (!userId) {
      return c.json({ error: 'Missing required field: userId' }, 400);
    }

    // Validate blockchain
    const supportedBlockchains = ['ARC-TESTNET', 'ETH-SEPOLIA', 'BASE-SEPOLIA', 'MATIC-AMOY', 'SOL-DEVNET'];
    if (!supportedBlockchains.includes(blockchain)) {
      return c.json({ 
        error: 'Unsupported blockchain',
        supported: supportedBlockchains
      }, 400);
    }

    // Validate account type
    if (!['EOA', 'SCA'].includes(accountType)) {
      return c.json({ 
        error: 'Invalid account type',
        supported: ['EOA', 'SCA']
      }, 400);
    }

    // Check if user already has a wallet for this blockchain
    const client = getSupabaseClient();
    const { data: existingWallet } = await client
      .from('developer_wallets')
      .select('*')
      .eq('user_id', userId.toLowerCase())
      .eq('blockchain', blockchain)
      .single();

    if (existingWallet) {
      return c.json({
        success: true,
        wallet: existingWallet,
        message: 'Wallet already exists for this blockchain'
      });
    }

    // Get Circle API credentials from environment
    const circleApiKey = Deno.env.get('CIRCLE_API_KEY');
    const circleEntitySecretCiphertext = Deno.env.get('CIRCLE_ENTITY_SECRET_CIPHERTEXT');
    const circleEntitySecret = Deno.env.get('CIRCLE_ENTITY_SECRET'); // Fallback
    const circleWalletSetId = Deno.env.get('CIRCLE_WALLET_SET_ID');

    // Log environment variables status (without exposing values)
    console.log('Environment variables check:', {
      hasApiKey: !!circleApiKey,
      hasEntitySecretCiphertext: !!circleEntitySecretCiphertext,
      entitySecretCiphertextLength: circleEntitySecretCiphertext?.length || 0,
      hasEntitySecret: !!circleEntitySecret,
      entitySecretLength: circleEntitySecret?.length || 0,
      hasWalletSetId: !!circleWalletSetId
    });

    if (!circleApiKey) {
      return c.json({ 
        error: 'Circle API credentials not configured',
        details: 'Please set CIRCLE_API_KEY in Edge Function secrets'
      }, 500);
    }

    // Entity Secret Ciphertext is preferred, but we can use Entity Secret as fallback
    if (!circleEntitySecretCiphertext && !circleEntitySecret) {
      return c.json({ 
        error: 'Circle Entity Secret not configured',
        details: 'Please set CIRCLE_ENTITY_SECRET_CIPHERTEXT or CIRCLE_ENTITY_SECRET in Edge Function secrets'
      }, 500);
    }

    // Helper function to re-encrypt entity secret ciphertext
    // Note: Circle requires a new ciphertext for each POST request
    async function reEncryptEntitySecretCiphertext(): Promise<string> {
      if (!circleEntitySecret) {
        throw new Error('CIRCLE_ENTITY_SECRET is required for re-encryption');
      }
      
      // Get entity public key
      const publicKeyResponse = await fetch('https://api.circle.com/v1/w3s/config/entity/publicKey', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${circleApiKey}`,
          'Content-Type': 'application/json',
        },
      });
      
      if (!publicKeyResponse.ok) {
        const errorText = await publicKeyResponse.text();
        throw new Error(`Failed to get public key: ${publicKeyResponse.status} ${errorText}`);
      }
      
      const publicKeyData = await publicKeyResponse.json();
      const entityPublicKey = publicKeyData.data?.publicKey;
      
      if (!entityPublicKey) {
        throw new Error('Failed to get entity public key from response');
      }
      
      // Convert entity secret from hex to bytes
      const entitySecretBytes = new Uint8Array(
        circleEntitySecret.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
      );
      
      // Process public key - it might be in PEM format or base64
      let publicKeyBuffer: Uint8Array;
      
      // Remove PEM headers if present and clean whitespace
      const keyWithoutHeaders = entityPublicKey
        .replace(/-----BEGIN PUBLIC KEY-----/g, '')
        .replace(/-----END PUBLIC KEY-----/g, '')
        .replace(/-----BEGIN RSA PUBLIC KEY-----/g, '')
        .replace(/-----END RSA PUBLIC KEY-----/g, '')
        .replace(/\s/g, '')
        .replace(/\n/g, '')
        .replace(/\r/g, '');
      
      try {
        // Try to decode as base64
        publicKeyBuffer = Uint8Array.from(atob(keyWithoutHeaders), c => c.charCodeAt(0));
      } catch (e) {
        // If base64 decoding fails, the key might already be in a different format
        // Log the error for debugging
        console.error('Failed to decode public key as base64:', e);
        console.error('Public key format (first 100 chars):', entityPublicKey.substring(0, 100));
        throw new Error(`Failed to decode public key as base64. Key format might be unsupported. Error: ${e instanceof Error ? e.message : String(e)}`);
      }
      
      // Import the public key for encryption
      const publicKey = await crypto.subtle.importKey(
        'spki',
        publicKeyBuffer,
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256',
        },
        false,
        ['encrypt']
      );
      
      // Encrypt the entity secret
      const encrypted = await crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP',
        },
        publicKey,
        entitySecretBytes
      );
      
      // Convert to base64
      return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    }

    // Create or get wallet set
    let walletSetId = circleWalletSetId;
    
    if (!walletSetId) {
      // Generate idempotency key for wallet set creation
      const idempotencyKey = crypto.randomUUID();
      
      // Entity Secret Ciphertext is required for wallet set creation
      // Re-encrypt it before each request
      let entitySecretCiphertextForRequest: string;
      if (circleEntitySecretCiphertext && circleEntitySecret) {
        try {
          // Try to re-encrypt the entity secret for this request
          entitySecretCiphertextForRequest = await reEncryptEntitySecretCiphertext();
        } catch (reEncryptError) {
          console.warn('Failed to re-encrypt entity secret, using existing ciphertext:', reEncryptError);
          // Fallback to existing ciphertext (may fail if reused)
          entitySecretCiphertextForRequest = circleEntitySecretCiphertext;
        }
      } else if (circleEntitySecretCiphertext) {
        // Use existing ciphertext (may fail if reused)
        entitySecretCiphertextForRequest = circleEntitySecretCiphertext;
      } else {
        return c.json({ 
          error: 'Circle Entity Secret Ciphertext required',
          details: 'CIRCLE_ENTITY_SECRET_CIPHERTEXT or CIRCLE_ENTITY_SECRET must be set in Edge Function secrets to create wallet sets'
        }, 500);
      }
      
      // Create a new wallet set for this user
      const walletSetResponse = await fetch('https://api.circle.com/v1/w3s/developer/walletSets', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${circleApiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: `Wallet Set for ${userId.substring(0, 10)}...`,
          idempotencyKey: idempotencyKey,
          entitySecretCiphertext: entitySecretCiphertextForRequest
        })
      });

      if (!walletSetResponse.ok) {
        const errorText = await walletSetResponse.text();
        throw new Error(`Failed to create wallet set: ${walletSetResponse.status} ${errorText}`);
      }

      const walletSetData = await walletSetResponse.json();
      walletSetId = walletSetData.data?.walletSet?.id;
      
      if (!walletSetId) {
        throw new Error('Failed to get wallet set ID from response');
      }
    }

    // Re-encrypt Entity Secret Ciphertext for wallet creation
    // Circle requires a new ciphertext for each POST request
    let entitySecretCiphertextForWallet: string | undefined;
    
    if (circleEntitySecret) {
      try {
        // Try to re-encrypt the entity secret for this request
        entitySecretCiphertextForWallet = await reEncryptEntitySecretCiphertext();
      } catch (reEncryptError) {
        console.warn('Failed to re-encrypt entity secret for wallet creation:', reEncryptError);
        // Fallback to existing ciphertext if available
        if (circleEntitySecretCiphertext) {
          entitySecretCiphertextForWallet = circleEntitySecretCiphertext;
          console.warn('Using existing ciphertext (may fail if reused)');
        } else {
          // If we can't re-encrypt and don't have existing ciphertext, we can't proceed
          return c.json({ 
            error: 'Failed to generate entity secret ciphertext',
            details: 'Unable to re-encrypt entity secret and no existing ciphertext available. Please ensure CIRCLE_ENTITY_SECRET_CIPHERTEXT is set or fix the re-encryption process.'
          }, 500);
        }
      }
    } else if (circleEntitySecretCiphertext) {
      // If no entity secret but we have ciphertext, use it directly
      entitySecretCiphertextForWallet = circleEntitySecretCiphertext;
    } else {
      return c.json({ 
        error: 'Circle Entity Secret or Ciphertext required',
        details: 'Either CIRCLE_ENTITY_SECRET or CIRCLE_ENTITY_SECRET_CIPHERTEXT must be set in Edge Function secrets to create wallets'
      }, 500);
    }
    
    // Validate that we have ciphertext and it's not empty
    if (!entitySecretCiphertextForWallet || entitySecretCiphertextForWallet.trim().length === 0) {
      console.error('Entity Secret Ciphertext validation failed:', {
        isNull: entitySecretCiphertextForWallet === null,
        isUndefined: entitySecretCiphertextForWallet === undefined,
        isEmpty: entitySecretCiphertextForWallet === '',
        trimmedLength: entitySecretCiphertextForWallet?.trim().length || 0,
        hasCircleEntitySecret: !!circleEntitySecret,
        hasCircleEntitySecretCiphertext: !!circleEntitySecretCiphertext
      });
      return c.json({ 
        error: 'Entity Secret Ciphertext is required',
        details: 'Failed to obtain valid entity secret ciphertext for wallet creation. Please check your environment variables.'
      }, 500);
    }
    
    // Use Entity Secret Ciphertext (required for wallet creation)
    const entitySecretHeader: Record<string, string> = {
      'X-Entity-Secret-Ciphertext': entitySecretCiphertextForWallet
    };

    // Log for debugging (without exposing full secret)
    console.log('Creating wallet with:', {
      hasCiphertext: !!entitySecretCiphertextForWallet,
      ciphertextLength: entitySecretCiphertextForWallet.length,
      hasEntitySecret: !!circleEntitySecret,
      headerKey: 'X-Entity-Secret-Ciphertext',
      headerValueLength: entitySecretHeader['X-Entity-Secret-Ciphertext']?.length || 0,
      headerKeys: Object.keys(entitySecretHeader)
    });

    // Generate idempotency key for wallet creation
    const walletIdempotencyKey = crypto.randomUUID();

    // Prepare headers
    const requestHeaders: Record<string, string> = {
      'Authorization': `Bearer ${circleApiKey}`,
      'Content-Type': 'application/json',
      ...entitySecretHeader,
    };

    // Log headers (without exposing full secret)
    console.log('Request headers:', {
      hasAuth: !!requestHeaders['Authorization'],
      hasContentType: !!requestHeaders['Content-Type'],
      hasCiphertextHeader: !!requestHeaders['X-Entity-Secret-Ciphertext'],
      ciphertextHeaderLength: requestHeaders['X-Entity-Secret-Ciphertext']?.length || 0,
      allHeaderKeys: Object.keys(requestHeaders)
    });

    // Prepare request body
    const requestBody = {
      blockchains: [blockchain],
      count: 1,
      walletSetId: walletSetId,
      accountType: accountType,
      idempotencyKey: walletIdempotencyKey,
      entitySecretCiphertext: entitySecretCiphertextForWallet,
      metadata: [{
        name: `Wallet for ${userId.substring(0, 10)}...`,
        refId: userId
      }]
    };

    // Log request body (without exposing full secret)
    console.log('Request body:', {
      blockchains: requestBody.blockchains,
      count: requestBody.count,
      walletSetId: requestBody.walletSetId,
      accountType: requestBody.accountType,
      hasIdempotencyKey: !!requestBody.idempotencyKey,
      hasEntitySecretCiphertext: !!requestBody.entitySecretCiphertext,
      entitySecretCiphertextLength: requestBody.entitySecretCiphertext?.length || 0,
      metadataCount: requestBody.metadata?.length || 0
    });

    const createWalletResponse = await fetch('https://api.circle.com/v1/w3s/developer/wallets', {
      method: 'POST',
      headers: requestHeaders,
      body: JSON.stringify(requestBody)
    });

    if (!createWalletResponse.ok) {
      const errorText = await createWalletResponse.text();
      console.error('Circle API error:', errorText);
      throw new Error(`Failed to create wallet: ${createWalletResponse.status} ${errorText}`);
    }

    const walletData = await createWalletResponse.json();
    const createdWallet = walletData.data?.wallets?.[0];

    if (!createdWallet) {
      throw new Error('No wallet returned from Circle API');
    }

    // Save wallet to database
    const { data: savedWallet, error: dbError } = await client
      .from('developer_wallets')
      .insert({
        user_id: userId.toLowerCase(),
        circle_wallet_id: createdWallet.id,
        circle_wallet_set_id: walletSetId,
        wallet_address: createdWallet.address,
        blockchain: createdWallet.blockchain,
        account_type: accountType,
        state: createdWallet.state || 'LIVE',
        custody_type: 'DEVELOPER'
      })
      .select()
      .single();

    if (dbError) {
      console.error('Database error:', dbError);
      throw new Error(`Failed to save wallet to database: ${dbError.message}`);
    }

    return c.json({
      success: true,
      wallet: savedWallet,
      circleWallet: createdWallet
    });
  } catch (error) {
    console.error('Error creating developer wallet:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ 
      error: 'Failed to create developer wallet',
      details: errorMessage 
    }, 500);
  }
});

// Get user's developer wallets
app.get('/wallets', async (c) => {
  try {
    const userId = c.req.query('userId');
    
    if (!userId) {
      return c.json({ error: 'Missing required parameter: userId' }, 400);
    }

    const client = getSupabaseClient();
    
    const { data: wallets, error } = await client
      .from('developer_wallets')
      .select('*')
      .eq('user_id', userId.toLowerCase())
      .order('created_at', { ascending: false });

    if (error) {
      throw new Error(`Failed to fetch wallets: ${error.message}`);
    }

    return c.json({
      success: true,
      wallets: wallets || []
    });
  } catch (error) {
    console.error('Error fetching developer wallets:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ 
      error: 'Failed to fetch developer wallets',
      details: errorMessage 
    }, 500);
  }
});

// Link Telegram ID to an existing developer wallet
app.post('/wallets/link-telegram', async (c) => {
  try {
    const body = await c.req.json().catch(() => ({}));

    const walletAddressRaw = body.wallet_address ?? body.walletAddress;
    const blockchainRaw = body.blockchain;
    const telegramUserIdRaw = body.telegram_user_id ?? body.telegramUserId;
    const signature = body.signature;
    const message = body.message;
    const privyUserIdRaw = body.privy_user_id ?? body.privyUserId ?? body.privy_did ?? body.privyDid;
    const validateTelegram = Boolean(body.validateTelegram ?? body.validate_telegram);

    const walletAddress = normalizeWalletAddress(walletAddressRaw);
    const blockchain = normalizeBlockchain(blockchainRaw);
    const telegramUserId = normalizeTelegramId(telegramUserIdRaw);
    const privyUserId = normalizePrivyUserId(privyUserIdRaw);

    if (!walletAddress || !blockchain || !telegramUserId) {
      return c.json({
        error: 'Missing required fields',
        required: ['wallet_address', 'blockchain', 'telegram_user_id']
      }, 400);
    }

    const client = getSupabaseClient();

    const { data: walletRecord, error: walletError } = await client
      .from('developer_wallets')
      .select('*')
      .eq('wallet_address', walletAddress)
      .eq('blockchain', blockchain)
      .single();

    if (walletError || !walletRecord) {
      return c.json({
        error: 'Developer wallet not found',
        details: `No wallet with address ${walletAddress} on ${blockchain}`
      }, 404);
    }

    // Short-circuit if already linked to same Telegram ID
    if (walletRecord.telegram_user_id && walletRecord.telegram_user_id === telegramUserId) {
      return c.json({
        success: true,
        wallet: walletRecord,
        message: 'Wallet already linked to this Telegram ID'
      });
    }

    const verificationDetails: Record<string, unknown> = {};
    let ownershipVerified = false;
    let privyUserData: any = null;

    if (signature && message) {
      const expectedAddresses = [walletAddress];
      if (walletRecord.user_id) {
        expectedAddresses.push(String(walletRecord.user_id).toLowerCase());
      }

      const signatureResult = await verifyWalletOwnershipWithSignature(expectedAddresses, message, signature);
      verificationDetails.signature = signatureResult;
      ownershipVerified = signatureResult.success;
    }

    if (!ownershipVerified && privyUserId) {
      const privyResult = await verifyWalletOwnershipWithPrivy(privyUserId, walletAddress);
      verificationDetails.privy = privyResult;
      ownershipVerified = privyResult.success;
      if (privyResult.user) {
        privyUserData = privyResult.user;
      }
    }

    if (!ownershipVerified) {
      return c.json({
        error: 'Wallet ownership verification failed',
        details: 'Provide a valid signature or Privy user context to confirm wallet ownership',
        verification: verificationDetails
      }, 403);
    }

    let telegramValidation: Record<string, unknown> | null = null;
    if (validateTelegram) {
      if (!privyUserData && privyUserId) {
        const fetchResult = await fetchPrivyUserById(privyUserId);
        if (fetchResult.success) {
          privyUserData = fetchResult.user;
        } else {
          telegramValidation = {
            success: false,
            reason: fetchResult.reason || 'user_not_found'
          };
        }
      }

      if (privyUserData) {
        const telegramIds = extractPrivyTelegramIds(privyUserData);
        const matches = telegramIds.includes(telegramUserId);
        telegramValidation = {
          success: matches,
          telegramIds
        };

        if (!matches) {
          return c.json({
            error: 'Telegram validation failed',
            details: 'Provided Telegram ID does not belong to the Privy user',
            validation: telegramValidation
          }, 403);
        }
      }
    }

    // Check for conflicts where Telegram ID is already linked to another wallet
    const { data: conflictingWallets } = await client
      .from('developer_wallets')
      .select('id, wallet_address, blockchain, user_id')
      .eq('telegram_user_id', telegramUserId);

    const conflicting = (conflictingWallets || []).find((row) => row.id !== walletRecord.id);

    if (conflicting) {
      console.warn('Telegram ID already linked to another wallet', {
        telegramUserId,
        existingWalletAddress: conflicting.wallet_address,
        existingBlockchain: conflicting.blockchain,
        requestedWalletAddress: walletAddress,
        requestedBlockchain: blockchain,
      });
    }

    const { data: updatedWallet, error: updateError } = await client
      .from('developer_wallets')
      .update({ telegram_user_id: telegramUserId })
      .eq('id', walletRecord.id)
      .select()
      .single();

    if (updateError) {
      throw new Error(`Failed to update wallet: ${updateError.message}`);
    }

    return c.json({
      success: true,
      wallet: updatedWallet,
      verification: verificationDetails,
      telegramValidation,
      conflict: conflicting ? {
        wallet_address: conflicting.wallet_address,
        blockchain: conflicting.blockchain,
        user_id: conflicting.user_id
      } : null
    });
  } catch (error) {
    console.error('Error linking Telegram ID:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({
      error: 'Failed to link Telegram ID',
      details: errorMessage
    }, 500);
  }
});

// Request testnet tokens for a wallet
app.post('/wallets/request-testnet-tokens', async (c) => {
  try {
    const { walletAddress, blockchain } = await c.req.json();
    
    if (!walletAddress) {
      return c.json({ error: 'Missing required field: walletAddress' }, 400);
    }

    if (!blockchain) {
      return c.json({ error: 'Missing required field: blockchain' }, 400);
    }

    // Validate that blockchain is a testnet
    const testnetBlockchains = ['ARC-TESTNET', 'ETH-SEPOLIA', 'BASE-SEPOLIA', 'MATIC-AMOY', 'OP-SEPOLIA', 'ARB-SEPOLIA', 'AVAX-FUJI', 'SOL-DEVNET', 'UNI-SEPOLIA'];
    if (!testnetBlockchains.includes(blockchain)) {
      return c.json({ 
        error: 'Invalid blockchain',
        message: 'Testnet tokens can only be requested for testnet blockchains',
        supported: testnetBlockchains
      }, 400);
    }

    // Get Circle API credentials
    const circleApiKey = Deno.env.get('CIRCLE_API_KEY');
    
    if (!circleApiKey) {
      return c.json({ 
        error: 'Circle API credentials not configured',
        details: 'Please set CIRCLE_API_KEY in Edge Function secrets'
      }, 500);
    }

    // Map blockchain to Circle's testnet format
    const blockchainMap: Record<string, string> = {
      'ARC-TESTNET': 'ARC-TESTNET',
      'ETH-SEPOLIA': 'ETH-SEPOLIA',
      'BASE-SEPOLIA': 'BASE-SEPOLIA',
      'MATIC-AMOY': 'MATIC-AMOY',
      'OP-SEPOLIA': 'OP-SEPOLIA',
      'ARB-SEPOLIA': 'ARB-SEPOLIA',
      'AVAX-FUJI': 'AVAX-FUJI',
      'SOL-DEVNET': 'SOL-DEVNET',
      'UNI-SEPOLIA': 'UNI-SEPOLIA'
    };

    const circleBlockchain = blockchainMap[blockchain] || blockchain;

    // Request testnet tokens (USDC and EURC)
    // Note: Circle API uses /v1/faucet/drips endpoint for programmatic faucet requests
    // For Developer-Controlled Wallets, we need to use the correct endpoint
    const response = await fetch('https://api.circle.com/v1/faucet/drips', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${circleApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        address: walletAddress,
        blockchain: circleBlockchain,
        usdc: true,
        eurc: true,
        native: false
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Circle API error:', errorText);
      throw new Error(`Failed to request testnet tokens: ${response.status} ${errorText}`);
    }

    // The API returns void, so we just check if it was successful
    return c.json({
      success: true,
      message: 'Testnet tokens requested successfully. USDC and EURC tokens will be sent to your wallet shortly.'
    });
  } catch (error) {
    console.error('Error requesting testnet tokens:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ 
      error: 'Failed to request testnet tokens',
      details: errorMessage 
    }, 500);
  }
});

// Toggle favorite status for social contact
app.patch('/contacts/social/favorite', async (c) => {
  try {
    const { userId, platform, socialId, isFavorite } = await c.req.json();
    
    if (!userId || !platform || !socialId || typeof isFavorite !== 'boolean') {
      return c.json({ 
        error: 'Missing required fields',
        required: ['userId', 'platform', 'socialId', 'isFavorite']
      }, 400);
    }

    const client = getSupabaseClient();
    
    let tableName: string;
    let idColumn: string;
    
    switch (platform) {
      case 'twitch':
        tableName = 'twitch_followed';
        idColumn = 'broadcaster_id';
        break;
      case 'twitter':
        tableName = 'twitter_followed';
        idColumn = 'twitter_user_id';
        break;
      case 'tiktok':
        tableName = 'tiktok_followed';
        idColumn = 'tiktok_user_id';
        break;
      case 'instagram':
        tableName = 'instagram_followed';
        idColumn = 'instagram_user_id';
        break;
      case 'telegram':
        tableName = 'telegram_contacts';
        idColumn = 'telegram_user_id';
        break;
      default:
        return c.json({ 
          error: 'Unsupported platform',
          supported: ['twitch', 'twitter', 'tiktok', 'instagram', 'telegram']
        }, 400);
    }
    
    const { error } = await client
      .from(tableName)
      .update({ is_favorite: isFavorite })
      .eq('user_id', userId)
      .eq(idColumn, socialId);

    if (error) {
      console.error('[SOCIAL CONTACT] Error updating favorite:', error);
      return c.json({ 
        error: 'Failed to update favorite status',
        details: error.message 
      }, 500);
    }

    return c.json({
      success: true,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[SOCIAL CONTACT] Unexpected error:', errorMessage);
    return c.json({ 
      error: 'Internal server error',
      details: errorMessage 
    }, 500);
  }
});

// ------------------------------
// Agent schedule helpers
// ------------------------------

interface SchedulePayload {
  userId: string;
  name: string;
  description?: string | null;
  sourceType: string;
  sourceConfig?: Record<string, unknown>;
  tokenSymbol?: string;
  tokenAddress?: string | null;
  network?: string;
  amountType?: string;
  amountValue: number | string;
  amountField?: string | null;
  currency?: string;
  scheduleType?: string;
  dayOfWeek?: number | null;
  dayOfMonth?: number | null;
  timeOfDay?: string | null;
  timezone?: string | null;
  cronExpression?: string | null;
  startAt?: string;
  endAt?: string | null;
  maxRuns?: number | null;
  skipStrategy?: string;
  metadata?: Record<string, unknown>;
  status?: string;
  paused?: boolean;
}

interface ScheduleRecord {
  id?: string;
  user_id: string;
  name: string;
  description: string | null;
  source_type: string;
  source_config: Record<string, unknown>;
  token_symbol: string;
  token_address: string | null;
  network: string;
  amount_type: string;
  amount_value: string;
  amount_field: string | null;
  currency: string;
  schedule_type: string;
  day_of_week: number | null;
  day_of_month: number | null;
  time_of_day: string;
  timezone: string;
  cron_expression: string | null;
  start_at: string;
  end_at: string | null;
  max_runs: number | null;
  status: string;
  paused: boolean;
  skip_strategy: string;
  last_run_at: string | null;
  next_run_at: string | null;
  total_runs: number;
  total_failures: number;
  total_amount: string;
  metadata: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
}

interface JobExecutionRecord {
  id: string;
  schedule_id: string;
  user_id: string;
  status: string;
  run_type: string;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  total_recipients: number;
  success_count: number;
  failure_count: number;
  total_amount: string;
  amount_currency: string;
  error_message: string | null;
  details: unknown;
  payload_snapshot: unknown;
  result: unknown;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

const ALLOWED_SOURCE_TYPES = new Set(['personal_contacts', 'twitch_table', 'manual', 'import']);
const ALLOWED_AMOUNT_TYPES = new Set(['fixed', 'percentage', 'formula']);
const ALLOWED_SCHEDULE_TYPES = new Set(['daily', 'weekly', 'monthly', 'custom']);
const ALLOWED_SKIP_STRATEGIES = new Set(['catch_up', 'skip', 'manual']);
const ALLOWED_STATUSES = new Set(['active', 'paused', 'completed', 'cancelled', 'draft']);

function ensureTimeOfDay(time?: string | null): string {
  if (!time || typeof time !== 'string') {
    return '09:00:00';
  }

  const trimmed = time.trim();
  const match = trimmed.match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
  if (!match) {
    return '09:00:00';
  }

  const hours = Math.min(Math.max(parseInt(match[1], 10) || 0, 0), 23);
  const minutes = Math.min(Math.max(parseInt(match[2], 10) || 0, 0), 59);
  const seconds = Math.min(Math.max(parseInt(match[3] ?? '0', 10) || 0, 0), 59);

  return [
    hours.toString().padStart(2, '0'),
    minutes.toString().padStart(2, '0'),
    seconds.toString().padStart(2, '0'),
  ].join(':');
}

function parseIntegerField(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const num = typeof value === 'string' ? parseInt(value, 10) : typeof value === 'number' ? Math.trunc(value) : NaN;
  return Number.isFinite(num) ? num : null;
}

function parseNumberAsString(value: unknown, fallback = '0'): string {
  if (value === null || value === undefined) return fallback;
  const num = typeof value === 'string' ? Number(value) : typeof value === 'number' ? value : NaN;
  if (!Number.isFinite(num)) {
    return fallback;
  }
  return num.toString();
}

function getNormalizedUserId(rawUserId: string | null | undefined): string | null {
  if (!rawUserId || typeof rawUserId !== 'string') {
    return null;
  }

  const normalizedWallet = normalizeWalletAddress(rawUserId);
  if (normalizedWallet) {
    return normalizedWallet;
  }

  return rawUserId.trim().toLowerCase();
}

function calculateNextRunAtFromRecord(
  record: Partial<ScheduleRecord> & { total_runs?: number },
  referenceDate?: Date
): string | null {
  if (!record) {
    return null;
  }

  const status = record.status ? record.status.toLowerCase() : 'active';

  if (record.paused || status === 'paused' || status === 'cancelled' || status === 'completed') {
    return null;
  }

  const maxRuns = typeof record.max_runs === 'number' ? record.max_runs : null;
  const totalRuns = typeof record.total_runs === 'number' ? record.total_runs : 0;
  if (maxRuns !== null && totalRuns >= maxRuns) {
    return null;
  }

  const startAt = record.start_at ? new Date(record.start_at) : new Date();
  if (Number.isNaN(startAt.getTime())) {
    return null;
  }

  const endAt = record.end_at ? new Date(record.end_at) : null;
  const reference = referenceDate ? new Date(referenceDate) : new Date();
  const effectiveReference = reference < startAt ? new Date(startAt) : reference;

  const timeString = ensureTimeOfDay(record.time_of_day);
  const [hours, minutes, seconds] = timeString.split(':').map((part) => parseInt(part, 10) || 0);

  const scheduleType = (record.schedule_type || 'weekly').toLowerCase();

  let candidate: Date;

  if (scheduleType === 'daily') {
    candidate = new Date(Date.UTC(
      effectiveReference.getUTCFullYear(),
      effectiveReference.getUTCMonth(),
      effectiveReference.getUTCDate(),
      hours,
      minutes,
      seconds,
    ));

    if (candidate <= effectiveReference) {
      candidate.setUTCDate(candidate.getUTCDate() + 1);
    }
  } else if (scheduleType === 'weekly') {
    const targetDow = typeof record.day_of_week === 'number'
      ? Math.max(0, Math.min(6, record.day_of_week))
      : startAt.getUTCDay();

    candidate = new Date(Date.UTC(
      effectiveReference.getUTCFullYear(),
      effectiveReference.getUTCMonth(),
      effectiveReference.getUTCDate(),
      hours,
      minutes,
      seconds,
    ));

    const currentDow = candidate.getUTCDay();
    let diff = targetDow - currentDow;
    if (diff < 0 || (diff === 0 && candidate <= effectiveReference)) {
      diff += 7;
    }
    candidate.setUTCDate(candidate.getUTCDate() + diff);
  } else if (scheduleType === 'monthly') {
    const targetDom = typeof record.day_of_month === 'number'
      ? Math.max(1, Math.min(31, record.day_of_month))
      : startAt.getUTCDate();

    const year = effectiveReference.getUTCFullYear();
    const month = effectiveReference.getUTCMonth();

    candidate = new Date(Date.UTC(year, month, targetDom, hours, minutes, seconds, 0));

    if (candidate <= effectiveReference) {
      const nextMonth = new Date(Date.UTC(year, month + 1, 1, hours, minutes, seconds, 0));
      const daysInMonth = new Date(Date.UTC(nextMonth.getUTCFullYear(), nextMonth.getUTCMonth() + 1, 0)).getUTCDate();
      const clampedDom = Math.min(targetDom, daysInMonth);
      candidate = new Date(Date.UTC(nextMonth.getUTCFullYear(), nextMonth.getUTCMonth(), clampedDom, hours, minutes, seconds, 0));
    }
  } else if (scheduleType === 'custom') {
    const nextRun = record.next_run_at ? new Date(record.next_run_at) : startAt;
    if (Number.isNaN(nextRun.getTime())) {
      return null;
    }
    if (nextRun <= effectiveReference) {
      return null;
    }
    candidate = nextRun;
  } else {
    candidate = new Date(startAt);
  }

  if (candidate < startAt) {
    candidate = new Date(startAt);
  }

  if (endAt && candidate > endAt) {
    return null;
  }

  return candidate.toISOString();
}

async function fetchScheduleById(client: any, scheduleId: string, userId: string): Promise<ScheduleRecord | null> {
  const { data, error } = await client
    .from('scheduled_jobs')
    .select('*')
    .eq('id', scheduleId)
    .eq('user_id', userId)
    .maybeSingle();

  if (error) {
    console.error('[SCHEDULE] Error fetching schedule by id:', error);
    throw new Error(error.message);
  }

  return data as ScheduleRecord | null;
}

function buildScheduleRecord(payload: SchedulePayload): ScheduleRecord {
  const normalizedUserId = getNormalizedUserId(payload.userId);
  if (!normalizedUserId) {
    throw new Error('Invalid userId');
  }

  if (!payload.name || typeof payload.name !== 'string') {
    throw new Error('Schedule name is required');
  }

  if (!payload.sourceType || !ALLOWED_SOURCE_TYPES.has(payload.sourceType)) {
    throw new Error(`Unsupported sourceType. Allowed: ${Array.from(ALLOWED_SOURCE_TYPES).join(', ')}`);
  }

  const scheduleType = (payload.scheduleType || 'weekly').toLowerCase();
  if (!ALLOWED_SCHEDULE_TYPES.has(scheduleType)) {
    throw new Error(`Unsupported scheduleType. Allowed: ${Array.from(ALLOWED_SCHEDULE_TYPES).join(', ')}`);
  }

  if (scheduleType === 'custom' && !payload.cronExpression) {
    throw new Error('cronExpression is required for custom schedules');
  }

  const amountType = (payload.amountType || 'fixed').toLowerCase();
  if (!ALLOWED_AMOUNT_TYPES.has(amountType)) {
    throw new Error(`Unsupported amountType. Allowed: ${Array.from(ALLOWED_AMOUNT_TYPES).join(', ')}`);
  }

  const skipStrategy = (payload.skipStrategy || 'catch_up').toLowerCase();
  if (!ALLOWED_SKIP_STRATEGIES.has(skipStrategy)) {
    throw new Error(`Unsupported skipStrategy. Allowed: ${Array.from(ALLOWED_SKIP_STRATEGIES).join(', ')}`);
  }

  const desiredStatus = payload.status ? payload.status.toLowerCase() : 'active';
  if (!ALLOWED_STATUSES.has(desiredStatus)) {
    throw new Error(`Unsupported status. Allowed: ${Array.from(ALLOWED_STATUSES).join(', ')}`);
  }

  const startAtRaw = payload.startAt ? new Date(payload.startAt) : new Date();
  if (Number.isNaN(startAtRaw.getTime())) {
    throw new Error('Invalid startAt value');
  }

  const endAtRaw = payload.endAt ? new Date(payload.endAt) : null;
  if (endAtRaw && Number.isNaN(endAtRaw.getTime())) {
    throw new Error('Invalid endAt value');
  }

  if (endAtRaw && endAtRaw <= startAtRaw) {
    throw new Error('endAt must be after startAt');
  }

  const timeOfDay = ensureTimeOfDay(payload.timeOfDay || payload.startAt);

  const baseRecord: ScheduleRecord = {
    user_id: normalizedUserId,
    name: payload.name.trim(),
    description: payload.description ? String(payload.description).trim() : null,
    source_type: payload.sourceType,
    source_config: payload.sourceConfig || {},
    token_symbol: payload.tokenSymbol || 'USDC',
    token_address: payload.tokenAddress || null,
    network: payload.network || 'ARC-TESTNET',
    amount_type: amountType,
    amount_value: parseNumberAsString(payload.amountValue, '0'),
    amount_field: payload.amountField || null,
    currency: payload.currency || 'USDC',
    schedule_type: scheduleType,
    day_of_week: scheduleType === 'weekly' ? parseIntegerField(payload.dayOfWeek) ?? startAtRaw.getUTCDay() : parseIntegerField(payload.dayOfWeek),
    day_of_month: scheduleType === 'monthly' ? parseIntegerField(payload.dayOfMonth) ?? startAtRaw.getUTCDate() : parseIntegerField(payload.dayOfMonth),
    time_of_day: timeOfDay,
    timezone: payload.timezone || 'UTC',
    cron_expression: payload.cronExpression || null,
    start_at: startAtRaw.toISOString(),
    end_at: endAtRaw ? endAtRaw.toISOString() : null,
    max_runs: parseIntegerField(payload.maxRuns) ?? null,
    status: desiredStatus,
    paused: Boolean(payload.paused),
    skip_strategy: skipStrategy,
    last_run_at: null,
    next_run_at: null,
    total_runs: 0,
    total_failures: 0,
    total_amount: '0',
    metadata: payload.metadata || {},
  };

  const nextRun = calculateNextRunAtFromRecord(baseRecord, new Date());
  baseRecord.next_run_at = nextRun || baseRecord.start_at;

  return baseRecord;
}

function mergeScheduleUpdates(existing: ScheduleRecord, updates: Partial<SchedulePayload>): ScheduleRecord {
  const merged: ScheduleRecord = {
    ...existing,
    name: updates.name ? updates.name.trim() : existing.name,
    description: updates.description !== undefined ? (updates.description ? String(updates.description).trim() : null) : existing.description,
    source_type: updates.sourceType && ALLOWED_SOURCE_TYPES.has(updates.sourceType) ? updates.sourceType : existing.source_type,
    source_config: updates.sourceConfig ? updates.sourceConfig : existing.source_config,
    token_symbol: updates.tokenSymbol || existing.token_symbol,
    token_address: updates.tokenAddress !== undefined ? updates.tokenAddress : existing.token_address,
    network: updates.network || existing.network,
    amount_type: updates.amountType && ALLOWED_AMOUNT_TYPES.has(updates.amountType) ? updates.amountType : existing.amount_type,
    amount_value: updates.amountValue !== undefined ? parseNumberAsString(updates.amountValue, existing.amount_value) : existing.amount_value,
    amount_field: updates.amountField !== undefined ? updates.amountField : existing.amount_field,
    currency: updates.currency || existing.currency,
    schedule_type: updates.scheduleType && ALLOWED_SCHEDULE_TYPES.has(updates.scheduleType) ? updates.scheduleType : existing.schedule_type,
    day_of_week: updates.dayOfWeek !== undefined ? parseIntegerField(updates.dayOfWeek) : existing.day_of_week,
    day_of_month: updates.dayOfMonth !== undefined ? parseIntegerField(updates.dayOfMonth) : existing.day_of_month,
    time_of_day: updates.timeOfDay !== undefined ? ensureTimeOfDay(updates.timeOfDay) : existing.time_of_day,
    timezone: updates.timezone || existing.timezone,
    cron_expression: updates.cronExpression !== undefined ? updates.cronExpression : existing.cron_expression,
    skip_strategy: updates.skipStrategy && ALLOWED_SKIP_STRATEGIES.has(updates.skipStrategy) ? updates.skipStrategy : existing.skip_strategy,
    metadata: updates.metadata ? { ...existing.metadata, ...updates.metadata } : existing.metadata,
    status: updates.status && ALLOWED_STATUSES.has(updates.status) ? updates.status : existing.status,
    paused: typeof updates.paused === 'boolean' ? updates.paused : existing.paused,
  };

  if (updates.startAt) {
    const startAtDate = new Date(updates.startAt);
    if (Number.isNaN(startAtDate.getTime())) {
      throw new Error('Invalid startAt value');
    }
    merged.start_at = startAtDate.toISOString();
  }

  if (updates.endAt !== undefined) {
    if (updates.endAt === null) {
      merged.end_at = null;
    } else {
      const endAtDate = new Date(updates.endAt);
      if (Number.isNaN(endAtDate.getTime())) {
        throw new Error('Invalid endAt value');
      }
      merged.end_at = endAtDate.toISOString();
    }
  }

  if (updates.maxRuns !== undefined) {
    merged.max_runs = parseIntegerField(updates.maxRuns);
  }

  if (updates.scheduleType && updates.scheduleType.toLowerCase() === 'custom' && !merged.cron_expression) {
    throw new Error('cronExpression is required for custom schedules');
  }

  return merged;
}

async function enrichSchedulesWithExecutions(client: any, schedules: ScheduleRecord[]): Promise<Array<ScheduleRecord & { last_execution: JobExecutionRecord | null }>> {
  if (!schedules || schedules.length === 0) {
    return [];
  }

  const scheduleIds = schedules.map((schedule) => schedule.id).filter(Boolean);
  if (scheduleIds.length === 0) {
    return schedules.map((schedule) => ({ ...schedule, last_execution: null }));
  }

  const { data: executionRows, error: execError } = await client
    .from('job_executions')
    .select('id,schedule_id,user_id,status,run_type,queued_at,started_at,finished_at,total_recipients,success_count,failure_count,total_amount,amount_currency,error_message,details,payload_snapshot,result,metadata,created_at,updated_at')
    .in('schedule_id', scheduleIds)
    .order('queued_at', { ascending: false })
    .limit(scheduleIds.length * 5);

  if (execError) {
    console.error('[SCHEDULE] Error loading executions:', execError);
    throw new Error(execError.message);
  }

  const executionMap = new Map<string, JobExecutionRecord>();
  if (executionRows) {
    for (const execution of executionRows as JobExecutionRecord[]) {
      if (!executionMap.has(execution.schedule_id)) {
        executionMap.set(execution.schedule_id, execution);
      }
    }
  }

  return schedules.map((schedule) => ({
    ...schedule,
    last_execution: executionMap.get(schedule.id || '') || null,
  }));
}

// ------------------------------
// Agent schedule endpoints
// ------------------------------

app.get('/agent/schedules', async (c) => {
  try {
    const userIdParam = c.req.query('userId');
    const normalizedUserId = getNormalizedUserId(userIdParam || '');

    if (!normalizedUserId) {
      return c.json({ error: 'Missing or invalid userId query parameter' }, 400);
    }

    const statusFilter = c.req.query('status');
    const includeHistory = c.req.query('includeHistory') === 'true';

    const client = getSupabaseClient();

    let query = client
      .from('scheduled_jobs')
      .select('*')
      .eq('user_id', normalizedUserId)
      .order('created_at', { ascending: false });

    if (statusFilter && ALLOWED_STATUSES.has(statusFilter)) {
      query = query.eq('status', statusFilter);
    }

    const { data, error } = await query;

    if (error) {
      console.error('[SCHEDULE] Error fetching schedules:', error);
      return c.json({ error: 'Failed to fetch schedules', details: error.message }, 500);
    }

    const schedules = Array.isArray(data) ? (data as ScheduleRecord[]) : [];
    const recordsWithNextRun = schedules.map((schedule) => {
      const nextRun = calculateNextRunAtFromRecord(schedule, new Date());
      return {
        ...schedule,
        next_run_at: nextRun,
      };
    });

    const enriched = includeHistory
      ? await enrichSchedulesWithExecutions(client, recordsWithNextRun)
      : recordsWithNextRun.map((schedule) => ({ ...schedule, last_execution: null }));

    return c.json({
      success: true,
      data: enriched,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[SCHEDULE] Unexpected error listing schedules:', error);
    return c.json({ error: 'Internal server error', details: errorMessage }, 500);
  }
});

app.post('/agent/schedules', async (c) => {
  try {
    const rawPayload = await c.req.json().catch(() => null);

    if (!rawPayload || typeof rawPayload !== 'object') {
      return c.json({ error: 'Invalid payload' }, 400);
    }

    const payload = rawPayload as SchedulePayload;

    const record = buildScheduleRecord(payload);
    const client = getSupabaseClient();

    const { data, error } = await client
      .from('scheduled_jobs')
      .insert(record)
      .select()
      .maybeSingle();

    if (error) {
      console.error('[SCHEDULE] Error inserting schedule:', error);
      return c.json({ error: 'Failed to create schedule', details: error.message }, 500);
    }

    const created = data as ScheduleRecord;
    const nextRun = calculateNextRunAtFromRecord(created, new Date());

    if (nextRun !== created.next_run_at) {
      await client
        .from('scheduled_jobs')
        .update({ next_run_at: nextRun })
        .eq('id', created.id);
      created.next_run_at = nextRun;
    }

    return c.json({
      success: true,
      data: created,
    }, 201);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[SCHEDULE] Unexpected error creating schedule:', error);
    return c.json({ error: 'Internal server error', details: errorMessage }, 500);
  }
});

app.get('/agent/schedules/:id', async (c) => {
  try {
    const scheduleId = c.req.param('id');
    const userIdParam = c.req.query('userId');
    const normalizedUserId = getNormalizedUserId(userIdParam || '');

    if (!scheduleId) {
      return c.json({ error: 'Missing schedule id' }, 400);
    }

    if (!normalizedUserId) {
      return c.json({ error: 'Missing or invalid userId query parameter' }, 400);
    }

    const client = getSupabaseClient();

    const schedule = await fetchScheduleById(client, scheduleId, normalizedUserId);
    if (!schedule) {
      return c.json({ error: 'Schedule not found' }, 404);
    }

    const nextRun = calculateNextRunAtFromRecord(schedule, new Date());
    schedule.next_run_at = nextRun;

    const limitParam = parseIntegerField(c.req.query('limit')) || 20;

    const { data: executions, error: execError } = await client
      .from('job_executions')
      .select('id,schedule_id,user_id,status,run_type,queued_at,started_at,finished_at,total_recipients,success_count,failure_count,total_amount,amount_currency,error_message,details,payload_snapshot,result,metadata,created_at,updated_at')
      .eq('schedule_id', scheduleId)
      .eq('user_id', normalizedUserId)
      .order('queued_at', { ascending: false })
      .limit(Math.min(100, Math.max(1, limitParam)));

    if (execError) {
      console.error('[SCHEDULE] Error fetching executions:', execError);
      return c.json({ error: 'Failed to fetch executions', details: execError.message }, 500);
    }

    return c.json({
      success: true,
      data: {
        schedule,
        executions: executions || [],
      },
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[SCHEDULE] Unexpected error fetching schedule:', error);
    return c.json({ error: 'Internal server error', details: errorMessage }, 500);
  }
});

app.get('/agent/schedules/:id/executions', async (c) => {
  try {
    const scheduleId = c.req.param('id');
    const userIdParam = c.req.query('userId');
    const normalizedUserId = getNormalizedUserId(userIdParam || '');
    const page = parseIntegerField(c.req.query('page')) || 1;
    const pageSize = parseIntegerField(c.req.query('pageSize')) || 20;

    if (!scheduleId) {
      return c.json({ error: 'Missing schedule id' }, 400);
    }

    if (!normalizedUserId) {
      return c.json({ error: 'Missing or invalid userId query parameter' }, 400);
    }

    const limit = Math.min(100, Math.max(1, pageSize));
    const offset = Math.max(0, (page - 1) * limit);

    const client = getSupabaseClient();

    const { data, error, count } = await client
      .from('job_executions')
      .select('id,schedule_id,user_id,status,run_type,queued_at,started_at,finished_at,total_recipients,success_count,failure_count,total_amount,amount_currency,error_message,details,payload_snapshot,result,metadata,created_at,updated_at', { count: 'exact' })
      .eq('schedule_id', scheduleId)
      .eq('user_id', normalizedUserId)
      .order('queued_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) {
      console.error('[SCHEDULE] Error fetching executions list:', error);
      return c.json({ error: 'Failed to fetch executions', details: error.message }, 500);
    }

    return c.json({
      success: true,
      data: data || [],
      pagination: {
        page,
        pageSize: limit,
        total: count ?? 0,
      },
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[SCHEDULE] Unexpected error listing executions:', error);
    return c.json({ error: 'Internal server error', details: errorMessage }, 500);
  }
});

app.patch('/agent/schedules/:id', async (c) => {
  try {
    const scheduleId = c.req.param('id');
    const rawPayload = await c.req.json().catch(() => null);

    if (!scheduleId) {
      return c.json({ error: 'Missing schedule id' }, 400);
    }

    if (!rawPayload || typeof rawPayload !== 'object') {
      return c.json({ error: 'Invalid payload' }, 400);
    }

    const payload = rawPayload as Partial<SchedulePayload>;

    const normalizedUserId = getNormalizedUserId(payload.userId || (payload as any).user_id);
    if (!normalizedUserId) {
      return c.json({ error: 'Missing or invalid userId' }, 400);
    }

    const client = getSupabaseClient();

    const existing = await fetchScheduleById(client, scheduleId, normalizedUserId);
    if (!existing) {
      return c.json({ error: 'Schedule not found' }, 404);
    }

    const merged = mergeScheduleUpdates(existing, payload);
    const nextRun = calculateNextRunAtFromRecord(merged, new Date());
    merged.next_run_at = nextRun;

    const { data, error } = await client
      .from('scheduled_jobs')
      .update({
        name: merged.name,
        description: merged.description,
        source_type: merged.source_type,
        source_config: merged.source_config,
        token_symbol: merged.token_symbol,
        token_address: merged.token_address,
        network: merged.network,
        amount_type: merged.amount_type,
        amount_value: merged.amount_value,
        amount_field: merged.amount_field,
        currency: merged.currency,
        schedule_type: merged.schedule_type,
        day_of_week: merged.day_of_week,
        day_of_month: merged.day_of_month,
        time_of_day: merged.time_of_day,
        timezone: merged.timezone,
        cron_expression: merged.cron_expression,
        start_at: merged.start_at,
        end_at: merged.end_at,
        max_runs: merged.max_runs,
        skip_strategy: merged.skip_strategy,
        metadata: merged.metadata,
        next_run_at: merged.next_run_at,
        status: merged.status,
        paused: merged.paused,
      })
      .eq('id', scheduleId)
      .eq('user_id', normalizedUserId)
      .select()
      .maybeSingle();

    if (error) {
      console.error('[SCHEDULE] Error updating schedule:', error);
      return c.json({ error: 'Failed to update schedule', details: error.message }, 500);
    }

    return c.json({
      success: true,
      data: data,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[SCHEDULE] Unexpected error updating schedule:', error);
    return c.json({ error: 'Internal server error', details: errorMessage }, 500);
  }
});

app.delete('/agent/schedules/:id', async (c) => {
  try {
    const scheduleId = c.req.param('id');
    const payload = await c.req.json().catch(() => ({})) as { userId?: string };
    const userIdParam = c.req.query('userId');

    if (!scheduleId) {
      return c.json({ error: 'Missing schedule id' }, 400);
    }

    const normalizedUserId = getNormalizedUserId(payload.userId || userIdParam || '');
    if (!normalizedUserId) {
      return c.json({ error: 'Missing or invalid userId' }, 400);
    }

    const client = getSupabaseClient();

    const existing = await fetchScheduleById(client, scheduleId, normalizedUserId);
    if (!existing) {
      return c.json({ error: 'Schedule not found' }, 404);
    }

    const { error } = await client
      .from('scheduled_jobs')
      .delete()
      .eq('id', scheduleId)
      .eq('user_id', normalizedUserId);

    if (error) {
      console.error('[SCHEDULE] Error deleting schedule:', error);
      return c.json({ error: 'Failed to delete schedule', details: error.message }, 500);
    }

    return c.json({ success: true });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[SCHEDULE] Unexpected error deleting schedule:', error);
    return c.json({ error: 'Internal server error', details: errorMessage }, 500);
  }
});

app.post('/agent/schedules/:id/run', async (c) => {
  try {
    const scheduleId = c.req.param('id');
    const payload = await c.req.json().catch(() => ({})) as { userId?: string; metadata?: Record<string, unknown>; note?: string };
    const userIdParam = c.req.query('userId');

    if (!scheduleId) {
      return c.json({ error: 'Missing schedule id' }, 400);
    }

    const normalizedUserId = getNormalizedUserId(payload.userId || userIdParam || '');
    if (!normalizedUserId) {
      return c.json({ error: 'Missing or invalid userId' }, 400);
    }

    const client = getSupabaseClient();
    const schedule = await fetchScheduleById(client, scheduleId, normalizedUserId);

    if (!schedule) {
      return c.json({ error: 'Schedule not found' }, 404);
    }

    const now = new Date();
    const nextRun = calculateNextRunAtFromRecord(schedule, now);

    const executionPayload = {
      schedule_id: scheduleId,
      user_id: normalizedUserId,
      status: 'pending',
      run_type: 'manual',
      queued_at: now.toISOString(),
      total_recipients: 0,
      success_count: 0,
      failure_count: 0,
      total_amount: '0',
      amount_currency: schedule.currency,
      error_message: null,
      details: [],
      payload_snapshot: {
        schedule,
        trigger_note: payload.note || null,
      },
      metadata: {
        ...schedule.metadata,
        ...payload.metadata,
        triggered_at: now.toISOString(),
      },
    };

    const { data: insertedExecution, error: insertError } = await client
      .from('job_executions')
      .insert(executionPayload)
      .select()
      .maybeSingle();

    if (insertError) {
      console.error('[SCHEDULE] Error enqueuing manual run:', insertError);
      return c.json({ error: 'Failed to enqueue manual run', details: insertError.message }, 500);
    }

    // Update schedule next run (preview) without altering totals yet
    if (nextRun) {
      const nextAfterManual = calculateNextRunAtFromRecord(
        {
          ...schedule,
          next_run_at: nextRun,
        },
        new Date(now.getTime() + 60_000)
      );

      await client
        .from('scheduled_jobs')
        .update({
          next_run_at: nextAfterManual || nextRun,
          last_run_at: schedule.last_run_at,
        })
        .eq('id', scheduleId);
    }

    return c.json({
      success: true,
      data: insertedExecution,
      message: 'Manual run queued. Worker will process it asynchronously.',
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('[SCHEDULE] Unexpected error enqueuing manual run:', error);
    return c.json({ error: 'Internal server error', details: errorMessage }, 500);
  }
});

// Wrapper for CORS handling at Deno.serve level
Deno.serve(async (req) => {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS, PUT, DELETE, PATCH',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, Accept, Origin',
    'Access-Control-Max-Age': '86400',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Type',
  };

  try {
    // Log incoming request for debugging
    const url = new URL(req.url);
    let pathname = url.pathname;
    console.log(`Incoming request: ${req.method} ${pathname}`);
    
    // Remove function name prefix from path
    // Supabase passes path as /smart-action/..., but Hono expects only path after function name
    if (pathname.startsWith('/smart-action')) {
      pathname = pathname.replace('/smart-action', '') || '/';
      console.log(`Normalized path: ${pathname}`);
    }
    
    // Handle OPTIONS requests with normalized path
    if (req.method === 'OPTIONS') {
      console.log('Handling OPTIONS preflight request for path:', pathname);
      return new Response(null, {
        status: 204,
        statusText: 'No Content',
        headers: new Headers(corsHeaders),
      });
    }
    
    // Create new URL with corrected path for Hono
    url.pathname = pathname;
    const normalizedReq = new Request(url.toString(), {
      method: req.method,
      headers: req.headers,
      body: req.body,
    });
    
    // Handle all other requests through Hono with normalized path
    const res = await app.fetch(normalizedReq);
    
    console.log(`Response status: ${res.status}`);

    // Always add CORS headers to response
    const headers = new Headers(res.headers);
    Object.entries(corsHeaders).forEach(([key, value]) => {
      headers.set(key, value);
    });

    return new Response(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers: headers,
    });
  } catch (error) {
    // Error handling with CORS headers
    console.error('Unhandled error in Edge Function:', error);
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    return new Response(JSON.stringify({ 
      error: 'Internal server error',
      details: errorMessage 
    }), {
      status: 500,
      statusText: 'Internal Server Error',
      headers: new Headers({
        ...corsHeaders,
        'Content-Type': 'application/json',
      }),
    });
  }
});