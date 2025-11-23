import express from "express"
import dotenv from "dotenv"
import { fileURLToPath } from "url"
import path from "path"
import crypto from "crypto"
import fs from "fs"
import cors from "cors"
import compression from "compression"

// ---------------- FIREBASE ADMIN (REALTIME DATABASE) ----------------
import admin from "firebase-admin";

const serviceAccount = {
  "type": "service_account",
  "project_id": "datawise-f3e20",
  "private_key_id": "0b09923c2719b9ebab95cbf1eec0a4468e240701",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCcsSf4q+YdiuFG\nXQ6/1UgXln6YScsYhZ/+Q8ySQdUAr3qmNVOZ5kEXqCtEiYr1djB9r6ep95LyDBj8\nkMJ11T6TAHnCIh8fWYOjucnWWcnwh06AMrvIWyZHEHcT8u5tNcWYE+2Z4y/qy/3V\nUtt0MjMwn0Y+X8RF+HEuMO+vsyjF3MaeEklb2SKTbIRyjWgoEycRihHRF00ymp9N\n7ye9dNakW0ObuNrdd3JvpbtCqBfmPYiLy+TzwH69LPTzmi8C2FJrs3S4zl9+OEAI\nM8ihsicKvJ9s2U4cPkVQ9q1M6tglo/bhW9Ee6nvo2ck7L1HTloa3zeDzrr0IBqP5\nL6kATiXdAgMBAAECggEANoXsjzqdiZUcW2QhMD5SZibPaUVwPtmseQj1g8UVjbYB\n+xjePNSivM0fNSuZJ12XdPys3ldQEhqEjUn/6ImpyvQk6hj+dGWtCUkqQwSeYKxs\nc+5zaj3RXXQMw2vKbEUEOy1gBabIsy6FZnf89ftL1bTud+DSBrjzBSwxExXH78Ue\nCPGsddUBCoEiHAU4HlConNow8lQ4mywfagQLxehx5zGpuTyxf0q5UC+GGjnQqhzZ\nyLu0eJ481Zb2sdDE3bsOH+Hw9o75ExdwxYw/sTh6+y3oQeCuyT6sVWTzBhwq5JaN\nbsxYp3ERMCsXGdgs6tMClJxfvb2O7btQ+BVJLJmTbwKBgQDNLXhfwiYDYCe3gWe2\nBDCbln+a7U3FjEbrHsue2uN8AXYz51yytHPpAfSYqRbOtHijv2SkLySHBOsva+FM\n9VCaAxT2CoNpnE3Q4kve3nvqGDkOxtapzvaXNQZggQ+gOc+Ef7V5r8wPHtbdf6E1\nSH48dS/c8cZJOF/W99NA4c/ZkwKBgQDDgSmh8KlC6kx6Toac2waqMzbmCtiAEs4x\nm+r0Ah2YXDAfuwYBzTevc5N8BEDcCPaEz5MjYAXzlFBibNkQxO2GDNjWXEFG1NZk\nVnOu/Wvt17DlT4hZ4vGMgme0Z5iXzGGZt/CVklCl4ZO0CUqDF24bcQIz1AwKxH71\nPtp0DbDozwKBgQC9ivb8B4BUd/zY4nvrwz0gTsz9U6IYEDnntSBIVU/32+XVlzOk\nh13Y8IyEhxhhxoj4RLR1lHN7JAkcWt3c2XcngBdaIGY8J0Af6x5J+mCg5tW3F+tx\nHZfiIgMNHc1QqHdToSMGEmhBw6ydHO3RKnIr6dpYkyYpuCGZloIbG0CHbwKBgHRX\ncMcFyDQh6dD+2eyOCrFOOOU8nwnYJwwulOsQNzxr39eCHFkGHpUyWhn7Df3i95Ch\nVhY/FkuVfyCTVbk893xGOOOXkuDr14luSPlhpdCsAoDzi1iyTLwo/j3FSHFNFue7\nJlhb8dJFIviIbucEEmoSHhVpoqDlvgeDl8xoOVbRAoGAMaBG6roXRYN1D2zFybfT\noHHeXD9PMdvD3mW1aiMsQaPVFIPVZ7qLT/p8kZ7hvNhz4P58x4to0sxOTj7gBCjn\nVrt6fnpWwOyzEw5UCVzkkxohVyDj7l4p/x9kWfaVFMJVLdhcFGUm4aN/qjqLssFZ\nihCaTJ1+GFdMuCo/sqAcfYE=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@datawise-f3e20.iam.gserviceaccount.com",
  "client_id": "101845840048598688212",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40datawise-f3e20.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://datawise-f3e20-default-rtdb.firebaseio.com",
  });
}

const db = admin.database();

dotenv.config()

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const CONFIG = {
  port: process.env.PORT || 3000,
  frontendUrl: process.env.FRONTEND_URL || `http://localhost:${process.env.PORT || 3000}`,
  baseUrl: process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`,
  hubnetApiKey: process.env.HUBNET_API_KEY,
  paystackSecretKey: process.env.PAYSTACK_SECRET_KEY,
  telecelApiKey: process.env.TELECEL_API_KEY,
  nodeEnv: process.env.NODE_ENV || "development",

  maxRetries: 1,
  baseDelay: 200,
  maxDelay: 3000,
  requestTimeout: 8000,
  keepAliveTimeout: 65000,
  headersTimeout: 66000,

  rateLimitWindow: 3 * 60 * 1000,
  rateLimitMax: 500,

  maxMemoryUsage: 512 * 1024 * 1024,
  cacheCleanupInterval: 60 * 1000,

  maxSockets: 200,
  maxFreeSockets: 50,
}

if (!CONFIG.hubnetApiKey || !CONFIG.paystackSecretKey) {
  console.error("❌ Missing required environment variables")
  process.exit(1)
}

const app = express()

// Enhanced logging utility
const logger = {
  info: (message, data = {}) => {
    console.log(`[INFO] ${new Date().toISOString()} - ${message}`, data)
  },
  error: (message, error = {}, data = {}) => {
    console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, {
      error: error.message || error,
      stack: error.stack,
      ...data,
    })
  },
  warn: (message, data = {}) => {
    console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, data)
  },
  debug: (message, data = {}) => {
    if (CONFIG.nodeEnv === "development") {
      console.log(`[DEBUG] ${new Date().toISOString()} - ${message}`, data)
    }
  },
}

app.set("trust proxy", 1)

app.use(
  compression({
    level: 3,
    threshold: 256,
    filter: (req, res) => {
      if (req.headers["x-no-compression"]) return false
      return compression.filter(req, res)
    },
  }),
)

const allowedOrigins = new Set([
  CONFIG.frontendUrl,
  "https://datawisegh.pro",
  "https://nityhub.online"
])

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.has(origin) || CONFIG.nodeEnv === "development") {
        callback(null, true)
      } else {
        callback(null, false)
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cache-Control", "X-Requested-With", "Accept", "Origin"],
    credentials: true,
    maxAge: 86400,
    optionsSuccessStatus: 204,
  }),
)

app.use(
  express.json({
    limit: "256kb",
    strict: true,
    type: "application/json",
  }),
)

app.use(
  express.urlencoded({
    extended: false,
    limit: "256kb",
    parameterLimit: 100,
  }),
)

const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Powered-By": "PBM-DataHub",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-DNS-Prefetch-Control": "off",
  "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
  "Pragma": "no-cache",
  "Expires": "0",
}

app.use((req, res, next) => {
  Object.entries(securityHeaders).forEach(([key, value]) => {
    res.setHeader(key, value)
  })
  next()
})

const rateLimitStore = new Map()

function rateLimit(req, res, next) {
  const clientId = req.ip || "unknown"
  const now = Date.now()
  const windowStart = now - CONFIG.rateLimitWindow

  if (!rateLimitStore.has(clientId)) {
    rateLimitStore.set(clientId, [])
  }

  const requests = rateLimitStore.get(clientId)
  const validRequests = requests.filter((time) => time > windowStart)

  if (validRequests.length >= CONFIG.rateLimitMax) {
    return res.status(429).json({
      status: "error",
      message: "Too many requests",
      retryAfter: Math.ceil(CONFIG.rateLimitWindow / 1000),
    })
  }

  validRequests.push(now)
  rateLimitStore.set(clientId, validRequests)
  next()
}

app.use(rateLimit)

// Request signature validation middleware for transaction endpoints
function validateRequestSignature(req, res, next) {
  const transactionEndpoints = [
    '/api/process-wallet-purchase',
    '/api/process-telecel-purchase',
    '/api/verify-payment',
    '/api/retry-transaction'
  ]
  
  if (transactionEndpoints.some(endpoint => req.path.includes(endpoint))) {
    // Validate request timestamp (prevent replay attacks)
    const requestTime = Date.now()
    const timestamp = req.headers['x-request-timestamp']
    
    if (timestamp) {
      const timeDiff = Math.abs(requestTime - parseInt(timestamp))
      if (timeDiff > 300000) { // 5 minutes
        logger.warn("Request timestamp too old", { 
          timestamp, 
          requestTime, 
          timeDiff, 
          ip: req.ip,
          path: req.path 
        })
        return res.status(400).json({
          status: "error",
          message: "Request timestamp too old",
          timestamp: new Date().toISOString(),
        })
      }
    }
    
    // Validate user agent
    const userAgent = req.headers['user-agent']
    if (!userAgent || userAgent.length < 10) {
      logger.warn("Suspicious user agent", { 
        userAgent, 
        ip: req.ip, 
        path: req.path 
      })
      return res.status(400).json({
        status: "error",
        message: "Invalid request",
        timestamp: new Date().toISOString(),
      })
    }
    
    // Log transaction attempts for monitoring
    logger.info("Transaction endpoint accessed", {
      path: req.path,
      method: req.method,
      ip: req.ip,
      userAgent: userAgent?.substring(0, 50),
      timestamp: new Date().toISOString(),
    })
  }
  
  next()
}

app.use(validateRequestSignature)

const publicDir = path.join(__dirname, "public")
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true })
}

app.use(
  express.static(publicDir, {
    maxAge: CONFIG.nodeEnv === "production" ? "1d" : "1h",
    etag: true,
    lastModified: true,
    setHeaders: (res, path) => {
      if (path.endsWith(".html")) {
        res.setHeader("Cache-Control", "no-cache")
      }
    },
  }),
)

class TransactionStore {
  constructor() {
    this._store = new Map()
    this._maxAge = 6 * 60 * 60 * 1000
    this._maxSize = 2000
    this.setupPeriodicCleanup()
  }

  setupPeriodicCleanup() {
    setInterval(() => {
      this.cleanup()
      this.memoryCleanup()
    }, CONFIG.cacheCleanupInterval)
  }

  memoryCleanup() {
    if (this._store.size > this._maxSize) {
      const entries = Array.from(this._store.entries())
      entries.sort((a, b) => a[1].timestamp - b[1].timestamp)
      const toDelete = entries.slice(0, this._store.size - this._maxSize)
      toDelete.forEach(([key]) => this._store.delete(key))
    }
  }

  has(reference) {
    return this._store.has(reference)
  }

  add(reference, metadata = {}) {
    this._store.set(reference, {
      timestamp: Date.now(),
      ...metadata,
    })
    return this
  }

  get(reference) {
    return this._store.get(reference)
  }

  cleanup(maxAgeMs = this._maxAge) {
    const now = Date.now()
    let count = 0

    for (const [reference, metadata] of this._store.entries()) {
      if (now - metadata.timestamp > maxAgeMs) {
        this._store.delete(reference)
        count++
      }
    }

    return count
  }
}

const processedTransactions = new TransactionStore()

// Duplicate attempt monitoring
const duplicateAttempts = new Map()
const MAX_DUPLICATE_ATTEMPTS = 5
const DUPLICATE_ATTEMPT_WINDOW = 10 * 60 * 1000 // 10 minutes

function recordDuplicateAttempt(identifier, type = 'transaction') {
  const key = `${type}_${identifier}`
  const now = Date.now()
  
  if (!duplicateAttempts.has(key)) {
    duplicateAttempts.set(key, [])
  }
  
  const attempts = duplicateAttempts.get(key)
  attempts.push(now)
  
  // Keep only attempts within the window
  const validAttempts = attempts.filter(time => now - time < DUPLICATE_ATTEMT_WINDOW)
  duplicateAttempts.set(key, validAttempts)
  
  // Log suspicious activity
  if (validAttempts.length >= MAX_DUPLICATE_ATTEMPTS) {
    logger.error("SUSPICIOUS DUPLICATE ATTEMPTS DETECTED", {
      identifier,
      type,
      attempts: validAttempts.length,
      window: DUPLICATE_ATTEMPT_WINDOW,
      timestamp: new Date().toISOString(),
    })
  }
  
  return validAttempts.length
}

function checkDuplicateAttempts(identifier, type = 'transaction') {
  const key = `${type}_${identifier}`
  const attempts = duplicateAttempts.get(key) || []
  const now = Date.now()
  const validAttempts = attempts.filter(time => now - time < DUPLICATE_ATTEMT_WINDOW)
  
  return {
    count: validAttempts.length,
    isSuspicious: validAttempts.length >= MAX_DUPLICATE_ATTEMPTS,
    lastAttempt: validAttempts.length > 0 ? validAttempts[validAttempts.length - 1] : null
  }
}

// Enhanced transaction locking mechanism with multiple lock types
const transactionLocks = new Map()
const phoneTransactionLocks = new Map()
const userTransactionLocks = new Map()

function acquireTransactionLock(reference, timeout = 30000) {
  if (transactionLocks.has(reference)) {
    const lockTime = transactionLocks.get(reference)
    if (Date.now() - lockTime < timeout) {
      return false // Lock still active
    }
  }

  transactionLocks.set(reference, Date.now())
  return true
}

function acquirePhoneTransactionLock(phone, volume, network, timeout = 45000) {
  const phoneKey = `${phone}_${volume}_${network}`
  if (phoneTransactionLocks.has(phoneKey)) {
    const lockTime = phoneTransactionLocks.get(phoneKey)
    if (Date.now() - lockTime < timeout) {
      return false // Lock still active for this phone+volume+network
    }
  }

  phoneTransactionLocks.set(phoneKey, Date.now())
  return true
}

function acquireUserTransactionLock(userId, timeout = 30000) {
  if (userTransactionLocks.has(userId)) {
    const lockTime = userTransactionLocks.get(userId)
    if (Date.now() - lockTime < timeout) {
      return false // User has active transaction
    }
  }

  userTransactionLocks.set(userId, Date.now())
  return true
}

function releaseTransactionLock(reference) {
  transactionLocks.delete(reference)
}

function releasePhoneTransactionLock(phone, volume, network) {
  const phoneKey = `${phone}_${volume}_${network}`
  phoneTransactionLocks.delete(phoneKey)
}

function releaseUserTransactionLock(userId) {
  userTransactionLocks.delete(userId)
}

// Cleanup expired locks periodically
setInterval(() => {
  const now = Date.now()
  const timeout = 30000 // 30 seconds
  const phoneTimeout = 45000 // 45 seconds for phone locks

  // Cleanup transaction locks
  for (const [reference, lockTime] of transactionLocks.entries()) {
    if (now - lockTime > timeout) {
      transactionLocks.delete(reference)
    }
  }

  // Cleanup phone transaction locks
  for (const [phoneKey, lockTime] of phoneTransactionLocks.entries()) {
    if (now - lockTime > phoneTimeout) {
      phoneTransactionLocks.delete(phoneKey)
    }
  }

  // Cleanup user transaction locks
  for (const [userId, lockTime] of userTransactionLocks.entries()) {
    if (now - lockTime > timeout) {
      userTransactionLocks.delete(userId)
    }
  }
}, 60000) // Run every minute

function generateReference(prefix = "DATA") {
  const timestamp = Date.now()
  const random = crypto.randomBytes(2).toString("hex")
  return `${prefix}_${timestamp}_${random}`
}

class CircuitBreaker {
  constructor(threshold = 3, timeout = 10000, name = "unknown") {
    this.threshold = threshold
    this.timeout = timeout
    this.name = name
    this.failureCount = 0
    this.lastFailureTime = null
    this.state = "CLOSED"
    this.successCount = 0
  }

  async call(fn) {
    if (this.state === "OPEN") {
      if (Date.now() - this.lastFailureTime > this.timeout) {
        this.state = "HALF_OPEN"
        logger.info(`Circuit breaker ${this.name} transitioning to HALF_OPEN`)
      } else {
        logger.warn(`Circuit breaker ${this.name} is OPEN, rejecting request`)
        throw new Error(`Service temporarily unavailable - ${this.name}`)
      }
    }

    try {
      const result = await fn()
      this.onSuccess()
      return result
    } catch (error) {
      this.onFailure()
      throw error
    }
  }

  onSuccess() {
    this.failureCount = 0
    this.successCount++

    if (this.state === "HALF_OPEN") {
      this.state = "CLOSED"
      this.successCount = 0
      logger.info(`Circuit breaker ${this.name} recovered to CLOSED`)
    }
  }

  onFailure() {
    this.failureCount++
    this.lastFailureTime = Date.now()
    this.successCount = 0

    if (this.failureCount >= this.threshold) {
      this.state = "OPEN"
      logger.error(`Circuit breaker ${this.name} opened after ${this.failureCount} failures`)
    }
  }

  getState() {
    return {
      state: this.state,
      failureCount: this.failureCount,
      successCount: this.successCount,
      lastFailureTime: this.lastFailureTime,
    }
  }
}

const paystackCircuitBreaker = new CircuitBreaker(3, 10000, "paystack")
const hubnetCircuitBreaker = new CircuitBreaker(3, 15000, "hubnet")
const telecelCircuitBreaker = new CircuitBreaker(3, 15000, "telecel")

const fetchWithRetry = async (url, options = {}, config = {}) => {
  const {
    maxRetries = CONFIG.maxRetries,
    baseDelay = CONFIG.baseDelay,
    maxDelay = CONFIG.maxDelay,
    timeout = CONFIG.requestTimeout,
    circuitBreaker = null,
  } = config

  let lastError = null

  const executeRequest = async () => {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), timeout)

        const fetchOptions = {
          ...options,
          signal: controller.signal,
          headers: {
            "User-Agent": "PBM-DataHub/5.0",
            Accept: "application/json",
            Connection: "keep-alive",
            ...options.headers,
          },
        }

        logger.debug(`Making request to ${url}`, { attempt: attempt + 1, maxRetries: maxRetries + 1 })

        const response = await fetch(url, fetchOptions)
        clearTimeout(timeoutId)

        if (!response.ok) {
          const errorText = await response.text()
          let errorData

          try {
            errorData = JSON.parse(errorText)
          } catch {
            errorData = { message: errorText || `HTTP ${response.status}` }
          }

          logger.error(`HTTP error ${response.status}`, errorData, { url, attempt })

          if (response.status >= 400 && response.status < 500 && response.status !== 429) {
            throw new Error(`Client error: ${errorData.message || response.status}`)
          }

          throw new Error(`Server error: ${errorData.message || response.status}`)
        }

        const contentType = response.headers.get("content-type")
        let data

        if (contentType && contentType.includes("application/json")) {
          const text = await response.text()
          data = JSON.parse(text)
        } else {
          const text = await response.text()
          data = JSON.parse(text)
        }

        logger.debug(`Request successful`, { url, attempt: attempt + 1 })
        return data
      } catch (error) {
        lastError = error

        if (error.name === "AbortError") {
          lastError = new Error("Request timeout")
        } else if (error.message.includes("Failed to fetch")) {
          lastError = new Error("Network error")
        }

        logger.error(`Request attempt ${attempt + 1} failed`, error, { url })

        if (error.message.includes("Client error") || attempt === maxRetries) {
          break
        }

        const delay = Math.min(baseDelay * Math.pow(1.5, attempt), maxDelay)
        await new Promise((resolve) => setTimeout(resolve, delay))
      }
    }

    throw lastError || new Error("Request failed")
  }

  if (circuitBreaker) {
    return circuitBreaker.call(executeRequest)
  } else {
    return executeRequest()
  }
}

async function initializePaystackPayment(payload) {
  return await fetchWithRetry(
    "https://api.paystack.co/transaction/initialize",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${CONFIG.paystackSecretKey}`,
      },
      body: JSON.stringify(payload),
    },
    {
      circuitBreaker: paystackCircuitBreaker,
      timeout: 8000,
      maxRetries: 2,
    },
  )
}

async function verifyPaystackPayment(reference) {
  return await fetchWithRetry(
    `https://api.paystack.co/transaction/verify/${reference}`,
    {
      headers: {
        Authorization: `Bearer ${CONFIG.paystackSecretKey}`,
        "Cache-Control": "no-cache",
      },
    },
    {
      circuitBreaker: paystackCircuitBreaker,
      timeout: 10000,
      maxRetries: 3,
    },
  )
}

async function checkHubnetBalance() {
  return await fetchWithRetry(
    "https://console.hubnet.app/live/api/context/business/transaction/check_balance",
    {
      method: "GET",
      headers: {
        token: `Bearer ${CONFIG.hubnetApiKey}`,
        "Content-Type": "application/json",
      },
    },
    {
      circuitBreaker: hubnetCircuitBreaker,
      timeout: 8000,
    },
  )
}

app.post("/webhook", express.json(), async (req, res) => {
  try {
    const payload = req.body;

    if (!payload?.data?.reference) {
      return res.status(400).json({ status: false, message: "Invalid webhook format" });
    }

    const { reference, status, msisdn, network, volume } = payload.data;
    const updatedAt = new Date().toISOString();

    // Search all users' orders for the order with this reference
    const ordersRoot = db.ref("orders");
    let found = false;
    let updatedUserId = null;
    let updatedOrderId = null;

    // Fetch all orders (could be optimized for large DBs)
    const ordersSnapshot = await ordersRoot.once("value");
    if (ordersSnapshot.exists()) {
      const ordersData = ordersSnapshot.val();
      for (const userId in ordersData) {
        const userOrders = ordersData[userId];
        for (const orderId in userOrders) {
          const order = userOrders[orderId];
          if (order && order.reference === reference) {
            // Update this order
            const orderRef = db.ref(`orders/${userId}/${orderId}`);
            await orderRef.update({
              status,
              network,
              phone: msisdn,
              volume,
              updatedAt,
            });
            found = true;
            updatedUserId = userId;
            updatedOrderId = orderId;
            break;
          }
        }
        if (found) break;
      }
    }

    // If not found, optionally create a new order (not typical, but fallback)
    if (!found) {
      // You may want to log this as a warning
      console.warn(`[WEBHOOK] Order reference ${reference} not found in any user's orders. No update performed.`);
    }

    // Also keep in-memory cache if needed
    processedTransactions.add(reference, {
      reference,
      phone: msisdn,
      network,
      volume,
      status,
      updatedFrom: "webhook",
      updatedAt,
    });

    console.log(`[WEBHOOK] Order ${reference} updated: ${status}`);
    res.status(200).json({ status: true, message: found ? "Webhook processed and order updated" : "Order not found, no update performed" });
  } catch (error) {
    console.error("Webhook processing failed:", error);
    res.status(500).json({ status: false, message: "Webhook processing failed" });
  }
});

// Update transaction status endpoint
app.get("/api/transaction-status/:reference", async (req, res) => {
  const { reference } = req.params;

  if (!reference) {
    return res.status(400).json({
      status: "error", 
      message: "Missing transaction reference"
    });
  }

  logger.info("Transaction status check", { reference });

  try {
    if (processedTransactions.has(reference)) {
      const metadata = processedTransactions.get(reference);
      
      return res.json({
        status: "success",
        message: "Transaction status retrieved",
        data: {
          reference,
          hubnetStatus: metadata.status || "Processing",
          network: metadata.network,
          phone: metadata.phone,
          volume: metadata.volume,
          updatedAt: metadata.updatedAt,
          updatedFrom: metadata.updatedFrom
        },
        timestamp: new Date().toISOString()
      });
    }

    // If not found in memory, check payment status
    const verifyData = await verifyPaystackPayment(reference);

    if (verifyData.status && verifyData.data.status === "success") {
      return res.json({
        status: "pending",
        message: "Payment verified, awaiting Hubnet confirmation",
        data: {
          reference,
          hubnetStatus: "Processing",
          paymentStatus: "success",
          paymentDetails: {
            amount: verifyData.data.amount / 100,
            phone: verifyData.data.metadata?.phone,
            volume: verifyData.data.metadata?.volume,
            network: verifyData.data.metadata?.network,
            paidAt: verifyData.data.paid_at
          }
        },
        timestamp: new Date().toISOString()
      });
    }

    res.json({
      status: "pending",
      message: "Awaiting Hubnet response",
      data: { 
        reference,
        hubnetStatus: "Pending",
        paymentStatus: verifyData.data?.status || "unknown"
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error("Error checking transaction status", error, { reference });
    res.status(500).json({
      status: "error",
      message: "Failed to check transaction status",
      timestamp: new Date().toISOString()
    });
  }
})

// Update Hubnet payload to include webhook
async function processHubnetTransaction(payload, network) {
  // Enhanced duplicate prevention - check reference first
  if (processedTransactions.has(payload.reference)) {
    const metadata = processedTransactions.get(payload.reference)
    if (metadata && metadata.hubnetResponse) {
      logger.info(`Transaction already processed`, { reference: payload.reference })
      return metadata.hubnetResponse
    }
    return {
      status: true,
      reason: "Already processed",
      code: "transaction already processed",
      message: "0000",
      transaction_id: `TXN-${payload.reference}`,
      reference: payload.reference,
      data: {
        status: true,
        code: "0000",
        message: "Order already processed.",
      },
    }
  }

  // Check for duplicate attempts
  const duplicateCheck = checkDuplicateAttempts(`${payload.phone}_${payload.volume}_${network}`, 'phone_transaction')
  if (duplicateCheck.isSuspicious) {
    logger.error("Suspicious duplicate attempts detected", {
      reference: payload.reference,
      phone: payload.phone,
      volume: payload.volume,
      network,
      attempts: duplicateCheck.count
    })
    throw new Error("SUSPICIOUS_ACTIVITY_DETECTED")
  }

  // Acquire phone-specific lock to prevent duplicate processing for same phone+volume+network
  const phoneLockAcquired = acquirePhoneTransactionLock(payload.phone, payload.volume, network)
  if (!phoneLockAcquired) {
    logger.warn(`Phone transaction lock conflict`, { 
      reference: payload.reference, 
      phone: payload.phone, 
      volume: payload.volume, 
      network 
    })
    recordDuplicateAttempt(`${payload.phone}_${payload.volume}_${network}`, 'phone_transaction')
    throw new Error("DUPLICATE_TRANSACTION_ATTEMPT")
  }

  try {
    const apiUrl = `https://console.hubnet.app/live/api/context/business/transaction/${network}-new-transaction`

    logger.info(`Processing Hubnet transaction`, { reference: payload.reference, network, apiUrl })

    // Add webhook URL to payload
    const hubnetPayload = {
      ...payload,
      webhook: "https://gigstest.onrender.com/webhook"
    };

    const data = await fetchWithRetry(
      apiUrl,
      {
        method: "POST",
        headers: {
          token: `Bearer ${CONFIG.hubnetApiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(hubnetPayload),
      },
      {
        circuitBreaker: hubnetCircuitBreaker,
        timeout: 15000,
        maxRetries: 1,
      },
    )

    if (
      data.event === "charge.rejected" &&
      data.status === "failed" &&
      data.message &&
      data.message.includes("insufficient")
    ) {
      logger.error(`Insufficient Hubnet balance`, { reference: payload.reference })
      throw new Error("INSUFFICIENT_HUBNET_BALANCE")
    }

    if (data.status === "failed") {
      const errorMessage = data.message || data.reason || "Transaction failed"
      logger.error(`Hubnet transaction failed`, { reference: payload.reference, error: errorMessage })
      throw new Error(`Hubnet API error: ${errorMessage}`)
    }

    processedTransactions.add(payload.reference, {
      network,
      phone: payload.phone,
      volume: payload.volume,
      hubnetResponse: data,
      processedAt: new Date().toISOString(),
    })

    logger.info(`Hubnet transaction successful`, { reference: payload.reference, transactionId: data.transaction_id })

    return data
  } finally {
    // Always release the phone lock
    releasePhoneTransactionLock(payload.phone, payload.volume, network)
  }
}

async function processTelecelTransaction(payload) {
  // Enhanced duplicate prevention - check reference first
  if (processedTransactions.has(payload.reference)) {
    const metadata = processedTransactions.get(payload.reference)
    if (metadata && metadata.telecelResponse) {
      logger.info(`Telecel transaction already processed`, { reference: payload.reference })
      return metadata.telecelResponse
    }
    return {
      success: true,
      message: "Already processed",
      data: {
        orderNumber: `TELECEL-${payload.reference}`,
        reference: payload.reference,
        status: "SUCCESSFUL",
        network: "Telecel",
        recipient: payload.recipient,
        dataAmount: `${payload.capacity}GB`,
        amountPaid: payload.amountPaid || 0,
        orderDate: new Date().toISOString(),
        statusDescription: "Order already processed.",
      },
    }
  }

  // Check for duplicate attempts
  const duplicateCheck = checkDuplicateAttempts(`${payload.recipient}_${payload.capacity}_telecel`, 'phone_transaction')
  if (duplicateCheck.isSuspicious) {
    logger.error("Suspicious duplicate attempts detected for Telecel", {
      reference: payload.reference,
      phone: payload.recipient,
      volume: payload.capacity,
      network: "telecel",
      attempts: duplicateCheck.count
    })
    throw new Error("SUSPICIOUS_ACTIVITY_DETECTED")
  }

  // Acquire phone-specific lock to prevent duplicate processing for same phone+volume+network
  const phoneLockAcquired = acquirePhoneTransactionLock(payload.recipient, payload.capacity, "telecel")
  if (!phoneLockAcquired) {
    logger.warn(`Telecel phone transaction lock conflict`, { 
      reference: payload.reference, 
      phone: payload.recipient, 
      volume: payload.capacity, 
      network: "telecel" 
    })
    recordDuplicateAttempt(`${payload.recipient}_${payload.capacity}_telecel`, 'phone_transaction')
    throw new Error("DUPLICATE_TRANSACTION_ATTEMPT")
  }

  try {
    const apiUrl = "https://console.ckgodsway.com/api/data-purchase"

    // Convert MB to GB and format properly for Telecel API
    const capacityInMB = parseInt(payload.capacity);
    const capacityInGB = (capacityInMB / 1000).toFixed(1);

    logger.info(`Processing Telecel transaction`, { 
      reference: payload.reference, 
      apiUrl, 
      capacityMB: capacityInMB, 
      capacityGB: capacityInGB 
    })

    const requestData = {
      networkKey: "TELECEL",
      recipient: payload.recipient,
      capacity: capacityInGB,
    }

    const data = await fetchWithRetry(
      apiUrl,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": CONFIG.telecelApiKey,
        },
        body: JSON.stringify(requestData),
      },
      {
        circuitBreaker: telecelCircuitBreaker,
        timeout: 15000,
        maxRetries: 1,
      },
    )

    if (!data.success) {
      const errorMessage = data.error || "Transaction failed"
      logger.error(`Telecel transaction failed`, { reference: payload.reference, error: errorMessage })
      throw new Error(`Telecel API error: ${errorMessage}`)
    }

    processedTransactions.add(payload.reference, {
      network: "telecel",
      phone: payload.recipient,
      volume: payload.capacity,
      telecelResponse: data,
      processedAt: new Date().toISOString(),
    })

    logger.info(`Telecel transaction successful`, { reference: payload.reference, orderNumber: data.data.orderNumber })

    return data
  } finally {
    // Always release the phone lock
    releasePhoneTransactionLock(payload.recipient, payload.capacity, "telecel")
  }
}

app.get("/health", (req, res) => {
  const memUsage = process.memoryUsage()
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
    environment: CONFIG.nodeEnv,
    services: {
      paystack: paystackCircuitBreaker.getState(),
      hubnet: hubnetCircuitBreaker.getState(),
      telecel: telecelCircuitBreaker.getState(),
    },
    processedTransactions: processedTransactions._store.size,
    security: {
      activeTransactionLocks: transactionLocks.size,
      activePhoneLocks: phoneTransactionLocks.size,
      activeUserLocks: userTransactionLocks.size,
      duplicateAttempts: duplicateAttempts.size,
    },
  })
})

app.get("/", (req, res) => {
  res.json({
    name: "PBM DATA HUB API",
    version: "5.0.0",
    status: "running",
    timestamp: new Date().toISOString(),
  })
})

app.get("/api/check-balance", async (req, res) => {
  try {
    const balanceData = await checkHubnetBalance()
    res.json({
      status: "success",
      data: balanceData,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error("Failed to check balance", error)
    res.status(500).json({
      status: "error",
      message: "Failed to retrieve balance",
      timestamp: new Date().toISOString(),
    })
  }
})

app.post("/api/reset-circuit-breaker/:service", (req, res) => {
  const { service } = req.params
  
  if (service === "telecel") {
    telecelCircuitBreaker.state = "CLOSED"
    telecelCircuitBreaker.failureCount = 0
    telecelCircuitBreaker.lastFailureTime = null
    telecelCircuitBreaker.successCount = 0
    
    logger.info(`Telecel circuit breaker manually reset`)
    
    res.json({
      status: "success",
      message: "Telecel circuit breaker reset successfully",
      service: service,
      state: telecelCircuitBreaker.getState(),
      timestamp: new Date().toISOString(),
    })
  } else {
    res.status(400).json({
      status: "error",
      message: "Invalid service. Only 'telecel' is supported",
      timestamp: new Date().toISOString(),
    })
  }
})

app.post("/api/initiate-payment", async (req, res) => {
  const { network, phone, volume, amount, email, fcmToken, paymentType, reference } = req.body

  logger.info("Payment initiation request", { paymentType, amount, email, reference })

  if (paymentType === "wallet") {
    if (!amount || !email) {
      return res.status(400).json({
        status: "error",
        message: "Missing required payment data",
      })
    }
  } else {
    if (!network || !phone || !volume || !amount || !email) {
      return res.status(400).json({
        status: "error",
        message: "Missing required payment data",
      })
    }

    if (!["mtn", "at", "big-time"].includes(network)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid network",
      })
    }

    if (!/^\d{10}$/.test(phone)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid phone number format",
      })
    }
  }

  const numAmount = Number(amount)
  if (isNaN(numAmount) || numAmount <= 0 || numAmount > 10000) {
    return res.status(400).json({
      status: "error",
      message: "Invalid amount",
    })
  }

  try {
    const prefix =
      paymentType === "wallet"
        ? "WALLET_DEPOSIT"
        : network === "mtn"
          ? "MTN_DATA"
          : network === "at"
            ? "AT_DATA"
            : "BT_DATA"

    const paymentReference = reference || generateReference(prefix)
    const amountInKobo = Math.round(numAmount * 100)

    const payload = {
      amount: amountInKobo,
      email,
      reference: paymentReference,
      callback_url: CONFIG.frontendUrl,
      metadata: {
        paymentType: paymentType || "bundle",
        fcmToken: fcmToken || null,
        custom_fields: [
          {
            display_name: paymentType === "wallet" ? "Wallet Deposit" : "Data Bundle",
            variable_name: paymentType === "wallet" ? "wallet_deposit" : "data_bundle",
            value:
              paymentType === "wallet"
                ? `₵${numAmount} Wallet Deposit`
                : `${volume}MB for ${phone} (${network.toUpperCase()})`,
          },
        ],
      },
    }

    if (paymentType !== "wallet") {
      payload.metadata.network = network
      payload.metadata.phone = phone
      payload.metadata.volume = volume
    }

    const data = await initializePaystackPayment(payload)

    if (!data.status || !data.data) {
      throw new Error("Payment initialization failed")
    }

    logger.info("Payment initialized successfully", { reference: paymentReference, amount: numAmount })

    res.json({
      status: "success",
      data: data.data,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error("Payment initialization failed", error, { amount: numAmount, paymentType })
    res.status(500).json({
      status: "error",
      message: "Payment initialization failed",
      timestamp: new Date().toISOString(),
    })
  }
})

app.post("/api/process-wallet-purchase", async (req, res) => {
  const { userId, network, phone, volume, amount, email, fcmToken, transactionKey } = req.body

  logger.info("Wallet purchase request", { userId, network, phone, volume, amount })

  if (!userId || !network || !phone || !volume || !amount || !email) {
    return res.status(400).json({
      status: "error",
      message: "Missing required data",
    })
  }

  if (!["mtn", "at", "big-time"].includes(network)) {
    return res.status(400).json({
      status: "error",
      message: "Invalid network",
    })
  }

  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).json({
      status: "error",
      message: "Invalid phone number",
    })
  }

  const numAmount = Number(amount)
  const numVolume = Number(volume)

  if (isNaN(numAmount) || numAmount <= 0 || isNaN(numVolume) || numVolume <= 0) {
    return res.status(400).json({
      status: "error",
      message: "Invalid amount or volume",
    })
  }

  // Acquire user lock to prevent multiple simultaneous transactions
  const userLockAcquired = acquireUserTransactionLock(userId)
  if (!userLockAcquired) {
    logger.warn("User transaction lock conflict", { userId, phone, volume, network })
    return res.status(409).json({
      status: "error",
      message: "You have a transaction in progress. Please wait.",
      timestamp: new Date().toISOString(),
    })
  }

  try {
    const prefix = network === "mtn" ? "MTN_PBM" : network === "at" ? "AT_PBM" : "BT_WALLET"
    const reference = generateReference(prefix)

    const hubnetPayload = {
      phone,
      volume: numVolume.toString(),
      reference,
      referrer: phone,
    }

    const hubnetData = await processHubnetTransaction(hubnetPayload, network)

    logger.info("Wallet purchase successful", { reference, userId, network, phone, volume: numVolume })

    res.json({
      status: "success",
      message: "Transaction completed successfully",
      data: {
        reference: reference,
        amount: numAmount,
        phone: phone,
        volume: numVolume,
        network: network,
        timestamp: Date.now(),
        transaction_id: hubnetData.transaction_id || hubnetData.data?.transaction_id || "N/A",
        hubnetResponse: hubnetData,
      },
      timestamp: new Date().toISOString(),
    })
  } catch (hubnetError) {
    logger.error("Wallet purchase failed", hubnetError, { userId, network, phone, volume: numVolume })

    if (hubnetError.message === "INSUFFICIENT_HUBNET_BALANCE") {
      return res.status(503).json({
        status: "error",
        errorCode: "INSUFFICIENT_HUBNET_BALANCE",
        message: "Service provider has insufficient balance",
        timestamp: new Date().toISOString(),
      })
    }

    if (hubnetError.message === "DUPLICATE_TRANSACTION_ATTEMPT") {
      return res.status(409).json({
        status: "error",
        message: "Duplicate transaction attempt detected",
        timestamp: new Date().toISOString(),
      })
    }

    res.status(500).json({
      status: "error",
      message: "Failed to process data bundle",
      timestamp: new Date().toISOString(),
    })
  } finally {
    // Always release the user lock
    releaseUserTransactionLock(userId)
  }
})

app.post("/api/process-telecel-purchase", async (req, res) => {
  const { userId, network, phone, volume, amount, email, fcmToken, transactionKey } = req.body

  logger.info("Telecel purchase request", { userId, network, phone, volume, amount })

  if (!userId || !network || !phone || !volume || !amount || !email) {
    return res.status(400).json({
      status: "error",
      message: "Missing required data",
    })
  }

  if (network !== "telecel") {
    return res.status(400).json({
      status: "error",
      message: "Invalid network for Telecel endpoint",
    })
  }

  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).json({
      status: "error",
      message: "Invalid phone number",
    })
  }

  const numAmount = Number(amount)
  const numVolume = Number(volume)

  if (isNaN(numAmount) || numAmount <= 0 || isNaN(numVolume) || numVolume <= 0) {
    return res.status(400).json({
      status: "error",
      message: "Invalid amount or volume",
    })
  }

  // Acquire user lock to prevent multiple simultaneous transactions
  const userLockAcquired = acquireUserTransactionLock(userId)
  if (!userLockAcquired) {
    logger.warn("User transaction lock conflict for Telecel", { userId, phone, volume, network })
    return res.status(409).json({
      status: "error",
      message: "You have a transaction in progress. Please wait.",
      timestamp: new Date().toISOString(),
    })
  }

  try {
    const prefix = "TELECEL_PBM"
    const reference = generateReference(prefix)

    const telecelPayload = {
      recipient: phone,
      capacity: numVolume.toString(),
      reference,
      amountPaid: numAmount,
    }

    const telecelData = await processTelecelTransaction(telecelPayload)

    logger.info("Telecel purchase successful", { reference, userId, network, phone, volume: numVolume })

    res.json({
      status: "success",
      message: "Telecel transaction completed successfully",
      data: {
        reference: reference,
        amount: numAmount,
        phone: phone,
        volume: numVolume,
        network: network,
        timestamp: Date.now(),
        orderNumber: telecelData.data.orderNumber || `TELECEL-${reference}`,
        telecelResponse: telecelData,
      },
      timestamp: new Date().toISOString(),
    })
  } catch (telecelError) {
    logger.error("Telecel purchase failed", telecelError, { userId, network, phone, volume: numVolume })

    if (telecelError.message === "DUPLICATE_TRANSACTION_ATTEMPT") {
      return res.status(409).json({
        status: "error",
        message: "Duplicate transaction attempt detected",
        timestamp: new Date().toISOString(),
      })
    }

    res.status(500).json({
      status: "error",
      message: "Failed to process Telecel data bundle",
      timestamp: new Date().toISOString(),
    })
  } finally {
    // Always release the user lock
    releaseUserTransactionLock(userId)
  }
})

// FIXED: Single, comprehensive payment verification endpoint
app.get("/api/verify-payment/:reference", async (req, res) => {
  const { reference } = req.params

  if (!reference) {
    return res.status(400).json({
      status: "error",
      message: "Missing payment reference",
    })
  }

  logger.info("Payment verification request", { reference })

  // Check if already processed in memory
  if (processedTransactions.has(reference)) {
    const metadata = processedTransactions.get(reference)
    logger.info("Transaction already processed (memory)", { reference })
    return res.json({
      status: "success",
      message: "Transaction already processed",
      data: {
        reference: reference,
        alreadyProcessed: true,
        processedAt: metadata.processedAt || new Date().toISOString(),
        hubnetResponse: metadata.hubnetResponse || null,
      },
      timestamp: new Date().toISOString(),
    })
  }

  // Acquire transaction lock to prevent race conditions
  if (!acquireTransactionLock(reference)) {
    logger.warn("Transaction lock conflict", { reference })
    return res.status(409).json({
      status: "error",
      message: "Transaction is currently being processed",
      retryAfter: 3,
    })
  }

  try {
    // Verify payment with Paystack
    logger.debug("Verifying payment with Paystack", { reference })
    const verifyData = await verifyPaystackPayment(reference)

    if (!verifyData.status) {
      logger.error("Paystack verification failed", { reference, response: verifyData })
      return res.json({
        status: "failed",
        message: "Payment verification failed",
        timestamp: new Date().toISOString(),
      })
    }

    const paymentData = verifyData.data
    logger.info("Paystack verification successful", {
      reference,
      status: paymentData.status,
      amount: paymentData.amount,
    })

    if (paymentData.status === "success") {
      const paymentType = paymentData.metadata?.paymentType || "bundle"

      // Handle wallet deposits
      if (paymentType === "wallet") {
        processedTransactions.add(reference, {
          type: "wallet_deposit",
          amount: paymentData.amount / 100,
          status: "success",
          processedAt: new Date().toISOString(),
          metadata: paymentData.metadata,
        })

        logger.info("Wallet deposit verified", { reference, amount: paymentData.amount / 100 })

        return res.json({
          status: "success",
          message: "Wallet deposit completed successfully",
          data: {
            reference: paymentData.reference,
            amount: paymentData.amount / 100,
            paymentType: "wallet",
            timestamp: new Date(paymentData.paid_at).getTime(),
          },
          timestamp: new Date().toISOString(),
        })
      }

      // Handle data bundle purchases
      const { phone, volume, network } = paymentData.metadata
      if (!phone || !volume || !network) {
        logger.error("Missing metadata for data bundle", { reference, metadata: paymentData.metadata })
        return res.status(400).json({
          status: "error",
          message: "Invalid payment metadata",
          timestamp: new Date().toISOString(),
        })
      }

      const hubnetPayload = {
        phone,
        volume: volume.toString(),
        reference,
        referrer: phone,
      }

      try {
        logger.debug("Processing Hubnet transaction for verified payment", { reference, network })
        const hubnetData = await processHubnetTransaction(hubnetPayload, network)

        logger.info("Data bundle processing successful", {
          reference,
          transactionId: hubnetData.transaction_id,
        })

        return res.json({
          status: "success",
          message: "Transaction completed successfully",
          data: {
            reference: paymentData.reference,
            amount: paymentData.amount / 100,
            phone: paymentData.metadata.phone,
            volume: paymentData.metadata.volume,
            network: paymentData.metadata.network,
            timestamp: new Date(paymentData.paid_at).getTime(),
            transaction_id: hubnetData.transaction_id || hubnetData.data?.transaction_id || "N/A",
            hubnetResponse: hubnetData,
          },
          timestamp: new Date().toISOString(),
        })
      } catch (hubnetError) {
        logger.error("Hubnet processing failed for verified payment", hubnetError, { reference })

        if (hubnetError.message === "INSUFFICIENT_HUBNET_BALANCE") {
          return res.json({
            status: "pending",
            paymentStatus: "success",
            hubnetStatus: "failed",
            message: "Payment successful but service provider has insufficient balance",
            data: {
              reference: paymentData.reference,
              amount: paymentData.amount / 100,
              phone: paymentData.metadata.phone,
              volume: paymentData.metadata.volume,
              network: paymentData.metadata.network,
              timestamp: new Date(paymentData.paid_at).getTime(),
            },
            timestamp: new Date().toISOString(),
          })
        }

        return res.json({
          status: "pending",
          paymentStatus: "success",
          hubnetStatus: "failed",
          message: "Payment successful but data bundle processing failed",
          data: {
            reference: paymentData.reference,
            amount: paymentData.amount / 100,
            phone: paymentData.metadata.phone,
            volume: paymentData.metadata.volume,
            network: paymentData.metadata.network,
            timestamp: new Date(paymentData.paid_at).getTime(),
          },
          timestamp: new Date().toISOString(),
        })
      }
    } else if (paymentData.status === "pending") {
      logger.info("Payment still pending", { reference })
      return res.json({
        status: "pending",
        paymentStatus: "pending",
        message: "Payment is being processed",
        timestamp: new Date().toISOString(),
      })
    } else {
      logger.info("Payment failed", { reference, status: paymentData.status })
      return res.json({
        status: "failed",
        paymentStatus: "failed",
        message: "Payment failed",
        data: paymentData,
        timestamp: new Date().toISOString(),
      })
    }
  } catch (error) {
    logger.error("Payment verification error", error, { reference })

    // Check if it's a circuit breaker error
    if (error.message.includes("Service temporarily unavailable")) {
      return res.status(503).json({
        status: "error",
        message: "Payment verification service temporarily unavailable. Please try again in a few minutes.",
        timestamp: new Date().toISOString(),
      })
    }

    res.status(500).json({
      status: "error",
      message: "Payment verification failed",
      timestamp: new Date().toISOString(),
    })
  } finally {
    releaseTransactionLock(reference)
  }
})

app.post("/api/retry-transaction/:reference", async (req, res) => {
  const { reference } = req.params
  const { network, phone, volume } = req.body

  logger.info("Transaction retry request", { reference, network, phone, volume })

  if (!reference || !network || !phone || !volume) {
    return res.status(400).json({
      status: "error",
      message: "Missing required parameters",
    })
  }

  // Acquire lock for retry
  if (!acquireTransactionLock(reference)) {
    return res.status(409).json({
      status: "error",
      message: "Transaction is currently being processed",
      retryAfter: 3,
    })
  }

  try {
    const verifyData = await verifyPaystackPayment(reference)

    if (!verifyData.status || verifyData.data.status !== "success") {
      return res.status(400).json({
        status: "error",
        message: "Cannot retry transaction - payment not successful",
      })
    }

    const hubnetPayload = {
      phone,
      volume: volume.toString(),
      reference,
      referrer: phone,
    }

    let existingData = null
    if (processedTransactions.has(reference)) {
      existingData = processedTransactions.get(reference)
      processedTransactions.add(reference, {
        ...existingData,
        retryAttempted: true,
        retryTimestamp: Date.now(),
      })
    }

    const hubnetData = await processHubnetTransaction(hubnetPayload, network)

    logger.info("Transaction retry successful", { reference, transactionId: hubnetData.transaction_id })

    res.json({
      status: "success",
      message: "Transaction retry completed",
      data: {
        reference,
        phone,
        volume,
        network,
        timestamp: Date.now(),
        transaction_id: hubnetData.transaction_id || hubnetData.data?.transaction_id || "N/A",
        hubnetResponse: hubnetData,
        previousAttempt: existingData ? true : false,
      },
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error("Transaction retry failed", error, { reference })
    res.status(500).json({
      status: "error",
      message: "Transaction retry failed",
      timestamp: new Date().toISOString(),
    })
  } finally {
    releaseTransactionLock(reference)
  }
})

app.get("/api/transaction-status/:reference", async (req, res) => {
  const { reference } = req.params

  if (!reference) {
    return res.status(400).json({
      status: "error",
      message: "Missing transaction reference",
    })
  }

  logger.info("Transaction status check", { reference })

  try {
    if (processedTransactions.has(reference)) {
      const metadata = processedTransactions.get(reference)

      return res.json({
        status: "success",
        message: "Transaction status retrieved",
        data: {
          reference,
          processed: true,
          processedAt: metadata.processedAt || new Date(metadata.timestamp).toISOString(),
          details: metadata,
        },
        timestamp: new Date().toISOString(),
      })
    } else {
      try {
        const verifyData = await verifyPaystackPayment(reference)

        if (verifyData.status && verifyData.data.status === "success") {
          return res.json({
            status: "pending",
            message: "Payment successful but data bundle not processed",
            data: {
              reference,
              processed: false,
              paymentStatus: "success",
              paymentDetails: {
                amount: verifyData.data.amount / 100,
                phone: verifyData.data.metadata?.phone,
                volume: verifyData.data.metadata?.volume,
                network: verifyData.data.metadata?.network,
                paidAt: verifyData.data.paid_at,
              },
            },
            timestamp: new Date().toISOString(),
          })
        } else {
          return res.json({
            status: "pending",
            message: "Payment not successful or pending",
            data: {
              reference,
              processed: false,
              paymentStatus: verifyData.data.status,
            },
            timestamp: new Date().toISOString(),
          })
        }
      } catch (paymentError) {
        logger.error("Error checking payment status", paymentError, { reference })
        return res.json({
          status: "unknown",
          message: "Transaction reference not found",
          data: {
            reference,
            processed: false,
          },
          timestamp: new Date().toISOString(),
        })
      }
    }
  } catch (error) {
    logger.error("Error checking transaction status", error, { reference })
    res.status(500).json({
      status: "error",
      message: "Failed to check transaction status",
      timestamp: new Date().toISOString(),
    })
  }
})

app.use("*", (req, res) => {
  res.status(404).json({
    status: "error",
    message: "Endpoint not found",
    path: req.originalUrl,
  })
})

app.use((err, req, res, next) => {
  logger.error("Unhandled error", err, { url: req.url, method: req.method })
  res.status(err.status || 500).json({
    status: "error",
    message: "Server error occurred",
  })
})

// Enhanced cleanup with better error handling
setInterval(() => {
  try {
    const now = Date.now()
    const windowStart = now - CONFIG.rateLimitWindow

    // Cleanup rate limiting
    for (const [clientId, requests] of rateLimitStore.entries()) {
      const validRequests = requests.filter((time) => time > windowStart)
      if (validRequests.length === 0) {
        rateLimitStore.delete(clientId)
      } else {
        rateLimitStore.set(clientId, validRequests)
      }
    }

    // Cleanup duplicate attempts
    let cleanedDuplicateAttempts = 0
    for (const [key, attempts] of duplicateAttempts.entries()) {
      const validAttempts = attempts.filter((time) => now - time < DUPLICATE_ATTEMT_WINDOW)
      if (validAttempts.length === 0) {
        duplicateAttempts.delete(key)
        cleanedDuplicateAttempts++
      } else {
        duplicateAttempts.set(key, validAttempts)
      }
    }

    // Cleanup processed transactions
    const cleanedTransactions = processedTransactions.cleanup()
    if (cleanedTransactions > 0 || cleanedDuplicateAttempts > 0) {
      logger.debug(`Cleanup: ${cleanedTransactions} expired transactions, ${cleanedDuplicateAttempts} duplicate attempt records`)
    }
  } catch (error) {
    logger.error("Error during cleanup", error)
  }
}, CONFIG.cacheCleanupInterval)

const server = app.listen(CONFIG.port, "0.0.0.0", () => {
  logger.info(`🚀 DataWise API Server v5.0 running on port ${CONFIG.port}`)
  logger.info(`🌍 Environment: ${CONFIG.nodeEnv}`)
  logger.info(`⚡ Optimized for Render hosting`)
})

server.keepAliveTimeout = CONFIG.keepAliveTimeout
server.headersTimeout = CONFIG.headersTimeout
server.timeout = CONFIG.requestTimeout

// Graceful shutdown
process.on("SIGTERM", () => {
  logger.info("SIGTERM received, shutting down gracefully")
  server.close(() => {
    logger.info("Process terminated")
    process.exit(0)
  })
})

export default app
