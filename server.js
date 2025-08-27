import express from "express"
import dotenv from "dotenv"
import { fileURLToPath } from "url"
import path from "path"
import crypto from "crypto"
import fs from "fs"
import cors from "cors"
import compression from "compression"

dotenv.config()

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const CONFIG = {
  port: process.env.PORT || 3000,
  frontendUrl: process.env.FRONTEND_URL || `http://localhost:${process.env.PORT || 3000}`,
  baseUrl: process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`,
  hubnetApiKey: process.env.HUBNET_API_KEY,
  paystackSecretKey: process.env.PAYSTACK_SECRET_KEY,
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
  "https://datawise-f3e20.web.app",
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

// Enhanced transaction locking mechanism
const transactionLocks = new Map()

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

function releaseTransactionLock(reference) {
  transactionLocks.delete(reference)
}

// Cleanup expired locks periodically
setInterval(() => {
  const now = Date.now()
  const timeout = 30000 // 30 seconds

  for (const [reference, lockTime] of transactionLocks.entries()) {
    if (now - lockTime > timeout) {
      transactionLocks.delete(reference)
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

async function processHubnetTransaction(payload, network) {
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

  const apiUrl = `https://console.hubnet.app/live/api/context/business/transaction/${network}-new-transaction`

  logger.info(`Processing Hubnet transaction`, { reference: payload.reference, network, apiUrl })

  const data = await fetchWithRetry(
    apiUrl,
    {
      method: "POST",
      headers: {
        token: `Bearer ${CONFIG.hubnetApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
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
    },
    processedTransactions: processedTransactions._store.size,
    activeLocks: transactionLocks.size,
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

  try {
    const prefix = network === "mtn" ? "MTN_DW" : network === "at" ? "AT_DW" : "BT_WALLET"
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

    res.status(500).json({
      status: "error",
      message: "Failed to process data bundle",
      timestamp: new Date().toISOString(),
    })
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

    for (const [clientId, requests] of rateLimitStore.entries()) {
      const validRequests = requests.filter((time) => time > windowStart)
      if (validRequests.length === 0) {
        rateLimitStore.delete(clientId)
      } else {
        rateLimitStore.set(clientId, validRequests)
      }
    }

    const cleanedTransactions = processedTransactions.cleanup()
    if (cleanedTransactions > 0) {
      logger.debug(`Cleaned up ${cleanedTransactions} expired transactions`)
    }
  } catch (error) {
    logger.error("Error during cleanup", error)
  }
}, CONFIG.cacheCleanupInterval)

const server = app.listen(CONFIG.port, "0.0.0.0", () => {
  logger.info(`🚀 PBM DATA HUB API Server v5.0 running on port ${CONFIG.port}`)
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

