require("dotenv").config()
const express = require("express")
const cors = require("cors")
const axios = require("axios")
const bodyParser = require("body-parser")
const admin = require("firebase-admin")

const app = express()
const port = process.env.PORT || 3000

// Initialize Firebase Admin
const serviceAccount = {
  type: "service_account",
  project_id: "gigshub-fec04",
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n") : undefined,
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_EMAIL
    ? `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
    : undefined,
}

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://gigshub-fec04-default-rtdb.firebaseio.com",
  })
  console.log("Firebase Admin initialized successfully")
} catch (error) {
  console.error("Firebase Admin initialization error:", error)
}

const database = admin.database()

// Middleware
app.use(
      cors({
        origin: ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5500", "http://127.0.0.1:5500", "https://gigshub.onrender.com"],
        credentials: true,
      }),
    )
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

// Constants
const FOSTER_API_KEY = process.env.FOSTER_API_KEY || "15532994719ccaad92f0121586ba734aba22defa"
const FOSTER_BASE_URL = "https://agent.jaybartservices.com/api/v1"
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || "sk_live_ad8e5341397f8245d1b3ba9f1790769259ddd253"
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || "pk_live_15c0e3b8d8e8c6b2c8a8e8c6b2c8a8e8c6b2c8a8"

// Foster API client setup
const fosterAPI = axios.create({
  baseURL: FOSTER_BASE_URL,
  headers: {
    "x-api-key": FOSTER_API_KEY,
    Accept: "application/json",
    "Content-Type": "application/json",
  },
  timeout: 30000,
})

// Utility Functions
// --- Crypto for API key generation and hashing ---
const crypto = require('crypto');

function generateApiKey() {
  return crypto.randomBytes(32).toString('hex'); // 64 chars
}

function hashApiKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

// --- API Key Auth Middleware ---
async function apiAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: "Missing API key" });
  const keyHash = hashApiKey(apiKey);
  const keySnap = await database.ref('apiKeys/' + keyHash).once('value');
  if (!keySnap.exists() || !keySnap.val().active) return res.status(403).json({ error: "Invalid API key" });
  req.userId = keySnap.val().userId;
  req.userData = (await database.ref('users/' + req.userId).once('value')).val();
  next();
}

// --- Idempotency Middleware ---
async function idempotency(req, res, next) {
  const idKey = req.headers['idempotency-key'];
  if (!idKey) return res.status(400).json({ error: "Missing Idempotency-Key header" });
  const path = `idempotency/${req.userId}/${idKey}`;
  const snap = await database.ref(path).once('value');
  if (snap.exists()) {
    return res.json(snap.val());
  }
  req.idempotencyPath = path;
  next();
}

// --- Rate Limiting Middleware ---
async function rateLimiter(req, res, next) {
  const keyHash = hashApiKey(req.headers['x-api-key'] || '');
  const now = new Date();
  const bucket = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}${String(now.getHours()).padStart(2,'0')}${String(now.getMinutes()).padStart(2,'0')}`;
  const path = `rateLimits/${keyHash}/${bucket}`;
  const snap = await database.ref(path).once('value');
  let count = snap.val() || 0;
  if (count >= 60) return res.status(429).json({ success: false, error: { code: "RATE_LIMITED", message: "Try again later" } });
  await database.ref(path).set(count + 1);
  next();
}
function logTransaction(type, data) {
  const timestamp = new Date().toISOString()
  console.log(`[${timestamp}] ${type}:`, JSON.stringify(data, null, 2))

  // Save to Firebase
  database
    .ref(`transaction_logs/${type}`)
    .push({
      ...data,
      timestamp,
    })
    .catch((error) => {
      console.error("Failed to log transaction to Firebase:", error)
    })
}

async function updateUserWallet(userId, amount) {
  try {
    const userRef = database.ref(`users/${userId}`)
    const snapshot = await userRef.once("value")
    const currentBalance = snapshot.val()?.walletBalance || 0
    const newBalance = currentBalance + amount

    await userRef.update({ walletBalance: newBalance })
    return newBalance
  } catch (error) {
    console.error("Error updating wallet:", error)
    throw error
  }
}

// API Routes
// --- API Key Generation/Regeneration ---
// --- Admin: Seed Bundles for All Networks ---
app.post('/v1/catalog/bundles/seed', async (req, res) => {
  // Only allow if a special admin API key is provided (for safety)
  const adminKey = req.headers['x-admin-key'];
  if (!adminKey || adminKey !== process.env.ADMIN_SEED_KEY) {
    return res.status(403).json({ error: 'Forbidden: Invalid admin key' });
  }

  // Use the networkData structure from app.js
  const networkData = {
    mtn: {
      prices: {
        '1GB': 5.5, '2GB': 12, '3GB': 18, '4GB': 23, '5GB': 27, '6GB': 34, '8GB': 42, '10GB': 47, '15GB': 74, '20GB': 90
      },
      agentPrices: {
        '1GB': 4.9, '2GB': 9.8, '3GB': 14.7, '4GB': 19.2, '5GB': 25, '6GB': 29, '8GB': 38.6, '10GB': 45, '15GB': 70, '20GB': 86, '30GB': 125, '50GB': 200, '100GB': 399
      },
      volumes: ['1GB', '2GB', '3GB', '4GB', '5GB', '6GB', '8GB', '10GB', '15GB', '20GB', '30GB', '50GB', '100GB']
    },
    at: {
      prices: {
        '1GB': 5, '2GB': 9, '3GB': 13, '4GB': 18, '5GB': 20, '6GB': 23, '7GB': 30, '8GB': 35, '9GB': 36, '10GB': 42, '15GB': 61.5, '20GB': 80, '40GB': 115, '50GB': 140
      },
      agentPrices: {
        '1GB': 4.3, '2GB': 8.6, '3GB': 12.5, '4GB': 18, '5GB': 20.6, '6GB': 24.8, '7GB': 28.6, '8GB': 33, '10GB': 40.2, '15GB': 60.2
      },
      volumes: ['1GB', '2GB', '3GB', '4GB', '5GB', '6GB', '7GB', '8GB', '9GB', '10GB', '15GB', '20GB', '40GB', '50GB']
    },
    telecel: {
      prices: {
        '5GB': 28, '10GB': 47, '15GB': 65, '20GB': 85, '25GB': 104, '30GB': 130, '40GB': 165, '50GB': 193, '100GB': 390
      },
      agentPrices: {
        '5GB': 23, '10GB': 42, '15GB': 60, '20GB': 80, '30GB': 117, '40GB': 157, '50GB': 187
      },
      volumes: ['5GB', '10GB', '15GB', '20GB', '25GB', '30GB', '40GB', '50GB', '100GB']
    }
  };

  // Build bundles for each network
  const bundles = {};
  Object.keys(networkData).forEach(network => {
    bundles[network] = {};
    networkData[network].volumes.forEach(volume => {
      bundles[network][volume] = {
        bundleId: volume,
        volume,
        price: networkData[network].prices[volume] || null,
        agentPrice: networkData[network].agentPrices[volume] || null,
        network,
        name: `${network.toUpperCase()} ${volume}`,
      };
    });
  });

  // Save to Firebase
  try {
    await database.ref('catalog/bundles').set(bundles);
    res.json({ success: true, bundles });
  } catch (err) {
    res.status(500).json({ error: 'Failed to seed bundles', details: err.message });
  }
});
app.post('/v1/auth/api-keys', async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "Missing userId" });
  const apiKey = generateApiKey();
  const keyHash = hashApiKey(apiKey);
  await database.ref(`apiKeys/${keyHash}`).set({ userId, active: true, createdAt: new Date().toISOString() });
  await database.ref(`users/${userId}`).update({ apiKeyHash: keyHash, apiKeyCreated: new Date().toISOString(), status: "active" });
  res.json({ apiKey }); // Show once only
});

// --- Catalog Endpoints ---

// Fetch networks from Realtime DB
app.get('/v1/catalog/networks', async (req, res) => {
  try {
    const snap = await database.ref('catalog/networks').once('value');
    const networksObj = snap.val() || {};
    const networks = Object.values(networksObj);
    res.json({ networks });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch networks', details: err.message });
  }
});

// Admin: Update networks in DB
app.post('/v1/catalog/networks', async (req, res) => {
  const { networks } = req.body;
  if (!Array.isArray(networks)) return res.status(400).json({ error: 'Networks must be an array' });
  try {
    await database.ref('catalog/networks').set(networks);
    res.json({ success: true, networks });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update networks', details: err.message });
  }
});

app.get('/v1/catalog/bundles', async (req, res) => {
  const { network } = req.query;
  try {
    const snap = await database.ref('catalog/bundles').once('value');
    const bundlesObj = snap.val() || {};
    let bundles = Object.values(bundlesObj);
    if (network) {
      bundles = bundles.filter(b => b.networkId === network);
    }
    res.json({ bundles });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch bundles', details: err.message });
  }
});

// Admin: Update bundles for a network
app.post('/v1/catalog/bundles', async (req, res) => {
  const { network, bundles } = req.body;
  if (!network || (!Array.isArray(bundles) && typeof bundles !== 'object')) return res.status(400).json({ error: 'Missing network or bundles (array or object)' });
  try {
    // If bundles is array, convert to object with bundleId keys if possible
    let bundlesToSave = bundles;
    if (Array.isArray(bundles)) {
      bundlesToSave = {};
      bundles.forEach((b, i) => { if (b && b.bundleId) bundlesToSave[b.bundleId] = b; else bundlesToSave[i] = b; });
    }
    await database.ref(`catalog/bundles/${network}`).set(bundlesToSave);
    res.json({ success: true, network, bundles: bundlesToSave });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update bundles', details: err.message });
  }
});

// --- Wallet Endpoints ---
app.get('/v1/wallet', apiAuth, async (req, res) => {
  const snap = await database.ref(`wallets/${req.userId}`).once('value');
  const wallet = snap.val() || { balance: 0 };
  res.json({ balance: wallet.balance, currency: 'GHS' });
});

app.post('/v1/wallet/topup/initiate', apiAuth, async (req, res) => {
  const { amount, customerEmail } = req.body;
  if (!amount || !customerEmail) return res.status(400).json({ error: "Missing amount or customerEmail" });
  // Use your existing Paystack logic here
  // ...existing code...
  res.status(501).json({ error: "Not implemented in this demo. Use /api/paystack/initialize for now." });
});

// --- Orders: Buy Bundle ---
app.post('/v1/orders', apiAuth, async (req, res) => {
  const { bundleId, phoneNumber } = req.body;
  if (!bundleId || !phoneNumber) {
    return res.status(400).json({ error: 'Missing bundleId or phoneNumber' });
  }
  // Fetch bundle
  const bundleSnap = await database.ref(`catalog/bundles/${bundleId}`).once('value');
  const bundle = bundleSnap.val();
  if (!bundle) {
    return res.status(404).json({ error: 'Bundle not found' });
  }
  // Fetch wallet
  const walletSnap = await database.ref(`wallets/${req.userId}`).once('value');
  const wallet = walletSnap.val() || { balance: 0 };
  if (wallet.balance < bundle.price) {
    return res.status(400).json({ error: 'Insufficient wallet balance' });
  }
  // Deduct wallet
  const newBalance = wallet.balance - bundle.price;
  await database.ref(`wallets/${req.userId}`).set({ balance: newBalance });
  // Create order
  const orderId = database.ref('orders').push().key;
  const order = {
    orderId,
    userId: req.userId,
    bundleId,
    phoneNumber,
    status: 'pending',
    amount: bundle.price,
    createdAt: Date.now()
  };
  await database.ref(`orders/${orderId}`).set(order);
  // Log transaction
  const txnId = database.ref('transactions').push().key;
  const txn = {
    txnId,
    userId: req.userId,
    amount: bundle.price,
    bundleId,
    status: 'success',
    createdAt: Date.now()
  };
  await database.ref(`transactions/${txnId}`).set(txn);
  res.json(order);
});

// --- Get Order Details ---
app.get('/v1/orders/:orderId', apiAuth, async (req, res) => {
  const { orderId } = req.params;
  const snap = await database.ref(`orders/${orderId}`).once('value');
  if (!snap.exists()) return res.status(404).json({ error: 'Order not found' });
  const order = snap.val();
  if (order.userId !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  res.json(order);
});

// --- Transactions Endpoint ---
app.get('/v1/transactions', apiAuth, async (req, res) => {
  const { status, limit } = req.query;
  const snap = await database.ref('transactions').orderByChild('createdAt').once('value');
  let txns = snap.val() ? Object.values(snap.val()) : [];
  txns = txns.filter(t => t.userId === req.userId);
  if (status) txns = txns.filter(t => t.status === status);
  if (limit) txns = txns.slice(-Number(limit));
  res.json({ transactions: txns });
});

// ✅ Health Check
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    service: "Gigs Hub API",
  })
})

// ✅ Check Console Balance
app.get("/api/check-balance", async (req, res) => {
  try {
    console.log("Checking console balance...")
    const response = await fosterAPI.get("/check-console-balance")

    logTransaction("balance_check", {
      success: true,
      data: response.data,
    })

    res.json(response.data)
  } catch (error) {
    console.error("Balance check error:", error.response?.data || error.message)

    logTransaction("balance_check_error", {
      error: error.response?.data || error.message,
    })

    res.status(error.response?.status || 500).json({
      error: error.response?.data?.error || "Failed to check balance",
      message: "Console balance check failed",
    })
  }
})

// ✅ Fetch Networks
app.get("/api/networks", async (req, res) => {
  try {
    console.log("Fetching networks...")
    const response = await fosterAPI.get("/fetch-networks")

    logTransaction("networks_fetch", {
      success: true,
      count: response.data.length,
    })

    res.json(response.data)
  } catch (error) {
    console.error("Networks fetch error:", error.response?.data || error.message)

    logTransaction("networks_fetch_error", {
      error: error.response?.data || error.message,
    })

    res.status(error.response?.status || 500).json({
      error: error.response?.data?.error || "Failed to fetch networks",
      message: "Networks fetch failed",
    })
  }
})

// ✅ Fetch Data Packages
app.get("/api/packages", async (req, res) => {
  try {
    console.log("Fetching data packages...")
    const response = await fosterAPI.get("/fetch-data-packages")

    logTransaction("packages_fetch", {
      success: true,
      count: response.data.length,
    })

    res.json(response.data)
  } catch (error) {
    console.error("Packages fetch error:", error.response?.data || error.message)

    logTransaction("packages_fetch_error", {
      error: error.response?.data || error.message,
    })

    res.status(error.response?.status || 500).json({
      error: error.response?.data?.error || "Failed to fetch packages",
      message: "Packages fetch failed",
    })
  }
})

// ✅ Buy iShare Package (AirtelTigo)
app.post("/api/buy-ishare", async (req, res) => {
  const { recipient_msisdn, shared_bundle, order_reference, userId } = req.body

  // Validation
  if (!recipient_msisdn || !shared_bundle || !order_reference || !userId) {
    return res.status(400).json({
      success: false,
      error: "Missing required fields",
      required: ["recipient_msisdn", "shared_bundle", "order_reference", "userId"],
    })
  }

  try {
    console.log("Processing iShare purchase:", { recipient_msisdn, shared_bundle, order_reference })

    const response = await fosterAPI.post("/buy-ishare-package", {
      recipient_msisdn,
      shared_bundle,
      order_reference,
    })

    const result = {
      success: true,
      message: response.data.response_msg || "iShare package purchased successfully",
      response_code: response.data.response_code,
      vendorTranxId: response.data.vendorTranxId,
      transaction_code: response.data.vendorTranxId,
    }

    logTransaction("ishare_purchase", {
      userId,
      recipient_msisdn,
      shared_bundle,
      order_reference,
      response: response.data,
      status: "success",
    })

    res.json(result)
  } catch (error) {
    console.error("iShare purchase error:", error.response?.data || error.message)

    const errorMessage =
      error.response?.data?.response_msg || error.response?.data?.message || "iShare package purchase failed"

    logTransaction("ishare_purchase_error", {
      userId,
      recipient_msisdn,
      shared_bundle,
      order_reference,
      error: error.response?.data || error.message,
      status: "failed",
    })

    res.status(400).json({
      success: false,
      message: errorMessage,
      response_code: error.response?.data?.response_code || "500",
      error: error.response?.data || error.message,
    })
  }
})

// ✅ Buy Other Package (MTN, Telecel, etc.)
app.post("/api/buy-bundle", async (req, res) => {
  const { recipient_msisdn, network_id, shared_bundle, order_reference, userId } = req.body

  // Validation
  if (!recipient_msisdn || !network_id || !shared_bundle || !order_reference || !userId) {
    return res.status(400).json({
      success: false,
      error: "Missing required fields",
      required: ["recipient_msisdn", "network_id", "shared_bundle", "order_reference", "userId"],
    })
  }

  try {
    console.log("Processing bundle purchase:", { recipient_msisdn, network_id, shared_bundle, order_reference })

    const response = await fosterAPI.post("/buy-other-package", {
      recipient_msisdn,
      network_id,
      shared_bundle,
    })

    const result = {
      success: true,
      message: response.data.message || "Package purchased successfully",
      transaction_code: response.data.transaction_code,
      data: response.data,
    }

    logTransaction("bundle_purchase", {
      userId,
      recipient_msisdn,
      network_id,
      shared_bundle,
      order_reference,
      response: response.data,
      status: "success",
    })

    res.json(result)
  } catch (error) {
    console.error("Bundle purchase error:", error.response?.data || error.message)

    const errorMessage = error.response?.data?.message || "Bundle purchase failed"

    logTransaction("bundle_purchase_error", {
      userId,
      recipient_msisdn,
      network_id,
      shared_bundle,
      order_reference,
      error: error.response?.data || error.message,
      status: "failed",
    })

    res.status(error.response?.status || 400).json({
      success: false,
      message: errorMessage,
      error: error.response?.data || error.message,
    })
  }
})

// ✅ Fetch iShare Transactions
app.get("/api/ishare-transactions", async (req, res) => {
  try {
    console.log("Fetching iShare transactions...")
    const response = await fosterAPI.get("/fetch-ishare-transactions")

    logTransaction("ishare_transactions_fetch", {
      success: true,
      count: response.data.length,
    })

    res.json(response.data)
  } catch (error) {
    console.error("iShare transactions fetch error:", error.response?.data || error.message)

    res.status(error.response?.status || 500).json({
      error: error.response?.data?.error || "Failed to fetch iShare transactions",
    })
  }
})

// ✅ Fetch Other Network Transactions
app.get("/api/other-transactions", async (req, res) => {
  try {
    console.log("Fetching other network transactions...")
    const response = await fosterAPI.get("/fetch-other-network-transactions")

    logTransaction("other_transactions_fetch", {
      success: true,
      count: response.data.length,
    })

    res.json(response.data)
  } catch (error) {
    console.error("Other transactions fetch error:", error.response?.data || error.message)

    res.status(error.response?.status || 500).json({
      error: error.response?.data?.error || "Failed to fetch other network transactions",
    })
  }
})

// ✅ Fetch Single iShare Transaction
app.post("/api/ishare-transaction", async (req, res) => {
  const { transaction_id } = req.body

  if (!transaction_id) {
    return res.status(400).json({ error: "Transaction ID is required" })
  }

  try {
    console.log("Fetching iShare transaction:", transaction_id)
    const response = await fosterAPI.post("/fetch-ishare-transaction", {
      transaction_id,
    })

    res.json(response.data)
  } catch (error) {
    console.error("iShare transaction fetch error:", error.response?.data || error.message)

    if (error.response?.status === 404) {
      res.status(404).json({ message: "Transaction not found." })
    } else {
      res.status(error.response?.status || 500).json({
        error: error.response?.data?.error || "Failed to fetch transaction",
      })
    }
  }
})

// ✅ Fetch Single Other Network Transaction
app.post("/api/other-transaction", async (req, res) => {
  const { transaction_id } = req.body

  if (!transaction_id) {
    return res.status(400).json({ error: "Transaction ID is required" })
  }

  try {
    console.log("Fetching other network transaction:", transaction_id)
    const response = await fosterAPI.post("/fetch-other-network-transaction", {
      transaction_id,
    })

    res.json(response.data)
  } catch (error) {
    console.error("Other network transaction fetch error:", error.response?.data || error.message)

    if (error.response?.status === 404) {
      res.status(404).json({ message: "Transaction not found." })
    } else {
      res.status(error.response?.status || 500).json({
        error: error.response?.data?.error || "Failed to fetch transaction",
      })
    }
  }
})

// ✅ Paystack - Initialize Payment
app.post("/api/paystack/initialize", async (req, res) => {
  const { email, amount, userId, depositAmount, charge } = req.body

  if (!email || !amount || !userId || !depositAmount || typeof charge === 'undefined') {
    return res.status(400).json({ error: "Missing required fields: email, amount, userId, depositAmount, charge" })
  }

  try {
    console.log("Initializing Paystack payment:", { email, amount, userId, depositAmount, charge })

    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email,
        amount: Math.round(Number.parseFloat(amount) * 100), // Convert to pesewas
        currency: "GHS",
        metadata: {
          userId,
          depositAmount: Number.parseFloat(depositAmount),
          charge: Number.parseFloat(charge),
          totalAmount: Number.parseFloat(amount),
          custom_fields: [
            {
              display_name: "Wallet Funding",
              variable_name: "wallet_funding",
              value: Number.parseFloat(depositAmount),
            },
            {
              display_name: "Charge",
              variable_name: "charge",
              value: Number.parseFloat(charge),
            },
            {
              display_name: "Total Amount",
              variable_name: "total_amount",
              value: Number.parseFloat(amount),
            },
          ],
        },
        channels: ["card", "bank", "ussd", "qr", "mobile_money", "bank_transfer"],
      },
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
          "Content-Type": "application/json",
        },
      },
    )

    const { reference, access_code, authorization_url } = response.data.data

    logTransaction("paystack_initialize", {
      userId,
      email,
      amount,
      depositAmount,
      charge,
      reference,
      success: true,
    })

    res.json({
      publicKey: PAYSTACK_PUBLIC_KEY,
      reference,
      accessCode: access_code,
      authorizationUrl: authorization_url,
    })
  } catch (error) {
    console.error("Paystack initialization error:", error.response?.data || error.message)

    logTransaction("paystack_initialize_error", {
      userId,
      email,
      amount,
      depositAmount,
      charge,
      error: error.response?.data || error.message,
    })

    res.status(500).json({
      error: "Failed to initialize payment",
      details: error.response?.data || error.message,
    })
  }
})

// ✅ Paystack - Verify Payment
app.get("/api/paystack/verify/:reference", async (req, res) => {
  const { reference } = req.params

  try {
    console.log("Verifying Paystack payment:", reference)

    // Prevent replay attacks: check if reference already processed
    const refCheck = await database.ref(`paystack_references/${reference}`).once('value');
    if (refCheck.exists()) {
      logTransaction("paystack_verify_replay_attempt", { reference, message: "Reference already processed" });
      return res.status(409).json({ error: "This payment reference has already been processed." });
    }

    const response = await axios.get(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
    })

    const paymentData = response.data.data
    console.log("[Paystack verify] Full paymentData:", JSON.stringify(paymentData, null, 2))

    // Strict metadata validation for depositAmount
    let userId = paymentData?.metadata?.userId
    let depositAmount = paymentData?.metadata?.depositAmount
    if ((!userId || !depositAmount) && paymentData?.metadata?.custom_fields) {
      // Try to extract from custom_fields array
      const userIdField = paymentData.metadata.custom_fields.find(f => f.display_name === 'Wallet Funding' || f.variable_name === 'wallet_funding')
      if (userIdField) {
        depositAmount = userIdField.value
      }
    }

    // Only allow success status and correct channel
    if (paymentData.status === "success" && paymentData.channel && ["card","bank","ussd","qr","mobile_money","bank_transfer"].includes(paymentData.channel)) {
      if (!userId || !depositAmount) {
        console.error("[Paystack verify] Missing userId or depositAmount in payment metadata:", paymentData.metadata)
        logTransaction("paystack_verify_error", {
          reference,
          error: "Missing userId or depositAmount in payment metadata",
          metadata: paymentData.metadata,
        })
        return res.status(400).json({ error: "Missing userId or depositAmount in payment metadata", metadata: paymentData.metadata })
      }

      // Mark reference as processed before updating wallet (atomicity)
      await database.ref(`paystack_references/${reference}`).set({ processed: true, userId, depositAmount, timestamp: new Date().toISOString() });

      // Update user wallet with only depositAmount
      const newBalance = await updateUserWallet(userId, Number.parseFloat(depositAmount))

      logTransaction("paystack_verify", {
        userId,
        depositAmount: Number.parseFloat(depositAmount),
        reference,
        newBalance,
        status: "success",
      })

      res.json({
        status: "success",
        balance: newBalance,
        amount: Number.parseFloat(depositAmount),
      })
    } else {
      // Suspicious or failed payment
      logTransaction("paystack_verify_error", {
        reference,
        paymentData,
        error: "Payment verification failed or suspicious channel",
      })
      res.status(400).json({ error: "Payment verification failed or suspicious channel", details: paymentData })
    }
  } catch (error) {
    console.error("[Paystack verify] Payment verification error:", error.response?.data || error.message)

    logTransaction("paystack_verify_error", {
      reference,
      error: error.response?.data || error.message,
    })

    res.status(500).json({
      error: "Payment verification failed",
      details: error.response?.data || error.message,
    })
  }
})

// ✅ Get Transaction Status
app.get("/api/transaction/:reference", async (req, res) => {
  const { reference } = req.params

  try {
    // Try iShare transaction first
    const ishareResponse = await fosterAPI.post("/fetch-ishare-transaction", {
      transaction_id: reference,
    })

    res.json({
      type: "ishare",
      data: ishareResponse.data,
    })
  } catch (ishareError) {
    try {
      // Try other network transaction
      const otherResponse = await fosterAPI.post("/fetch-other-network-transaction", {
        transaction_id: reference,
      })

      res.json({
        type: "other",
        data: otherResponse.data,
      })
    } catch (otherError) {
      res.status(404).json({
        error: "Transaction not found",
        reference,
      })
    }
  }
})

// ✅ Error Handler
app.use((err, req, res, next) => {
  console.error("Global error handler:", err)
  res.status(500).json({
    error: "Internal server error",
    message: err.message,
  })
})

// ✅ 404 Handler
app.use("*", (req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    path: req.originalUrl,
  })
})

// ✅ Start Server
const startServer = (attemptPort = port) => {
  const server = app
    .listen(attemptPort)
    .on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        console.log(`Port ${attemptPort} is busy, trying ${attemptPort + 1}...`)
        startServer(attemptPort + 1)
      } else {
        console.error("Server error:", err)
        process.exit(1)
      }
    })
    .on("listening", () => {
      const actualPort = server.address().port
      console.log(`🚀 Gigs Hub Server running at http://localhost:${actualPort}`)
      console.log(`📊 Health check: http://localhost:${actualPort}/api/health`)

      if (actualPort !== port) {
        console.warn(`⚠️  Port ${port} was busy. Server started on port ${actualPort}`)
        console.warn(`⚠️  Update your frontend to use port ${actualPort}`)
      }

      // Test Foster API connection
      fosterAPI
        .get("/check-console-balance")
        .then(() => console.log("✅ Foster API connection successful"))
        .catch(() => console.log("❌ Foster API connection failed - check API key"))
    })
}

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully")
  process.exit(0)
})

process.on("SIGINT", () => {
  console.log("SIGINT received, shutting down gracefully")
  process.exit(0)
})

startServer()

module.exports = app
