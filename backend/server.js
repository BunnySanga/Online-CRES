const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { NODE_ENV, PORT, allowlist } = require('./config/appConfig');
const path = require('path');
const fs = require('fs');

const app = express();

function setupMiddleware(app) {
  if (NODE_ENV === 'production') {
    app.set('trust proxy', 1);
  }
  app.use(helmet());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());
  if (NODE_ENV !== 'production') {
    app.use(
      cors({
        origin: (origin, callback) => {
          if (!origin) return callback(null, true);
          if (allowlist.has(origin)) return callback(null, true);
          return callback(new Error(`CORS not allowed from origin: ${origin}`));
        },
        credentials: true,
      })
    );
  }

  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: NODE_ENV === 'production' ? 200 : 10000,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/',
    handler: (req, res) => {
      return res
        .status(429)
        .json({
          error:
            'Too many requests (rate limit). Please slow down and try again shortly.',
        });
    },
  });
  app.use(limiter);
}

setupMiddleware(app);

// routes

/*
 * Purpose: Mount API route modules and health endpoints.
 */
function setupRoutes(app) {
  app.use('/api/auth', require('./routes/auth'));
  app.use('/api/elections', require('./routes/elections'));
  app.use('/api/nominations', require('./routes/nominations'));
  app.use('/api/votes', require('./routes/votes'));
  app.use('/api/policy', require('./routes/policy'));
  app.use('/api/audit', require('./routes/audit'));
  app.use('/api/admin', require('./routes/admin'));
  app.use('/api/students', require('./routes/students'));
  app.use('/api/notifications', require('./routes/notifications'));
  app.get('/api/health', (req, res) =>
    res.json({ ok: true, now: new Date().toISOString(), env: NODE_ENV })
  );
}

setupRoutes(app);

// Serve frontend build whenever it exists (useful locally and in production)
(() => {
  const distPath = path.join(__dirname, '../frontend/dist');
  if (fs.existsSync(distPath)) {
    app.use(express.static(distPath));
    // In Express 5, bare '*' is invalid. Use a regex to match all non-API GET requests.
    app.get(/^\/(?!api).*$/, (req, res) => {
      return res.sendFile(path.join(distPath, 'index.html'));
    });
    console.log(`[web] Serving frontend from: ${distPath}`);
  } else {
    console.warn('[web] No frontend build directory found at', distPath);
  }
})();

/*
 * Maintenance job: runs periodically to perform background tasks (cleanup OTPs, auto-close/activate elections, etc.).
 * Note: Currently scheduled with a 1s interval for development/demo. Consider increasing interval in production (e.g., 1m).
 */
const maintenanceJob = require('./utils/maintenanceJob');
const maintenanceIntervalMs = NODE_ENV === 'production' ? 60_000 : 1_000;
setInterval(maintenanceJob, maintenanceIntervalMs);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
