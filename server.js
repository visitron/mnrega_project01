const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
require('dotenv').config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Middleware to check authentication and redirect to login for dashboard.html
app.use((req, res, next) => {
  if (req.path === '/dashboard.html') {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      return res.redirect('/');
    }
    try {
      jwt.verify(auth.slice(7), JWT_SECRET);
    } catch (err) {
      return res.redirect('/');
    }
  }
  next();
});

const DATA_FILE = path.join(__dirname, 'data', 'response.json');

const API_BASE = 'https://api.data.gov.in/resource/ee03643a-ee4c-48c2-ac30-9f2ff26ab722';
const API_KEY = process.env.API_KEY || process.env.API_KEY_DATA || '';
// Database (Postgres) setup for user accounts
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const DATABASE_URL = process.env.DATABASE_URL || process.env.PG_CONNECTION_STRING || '';
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';

let db;
if (DATABASE_URL) {
  db = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
  // create users table if not exists
  (async () => {
    try {
      await db.query(`CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )`);
      console.log('Users table checked/created');
      // ensure query_cache table exists as well (used for per-user caching)
      await db.query(`CREATE TABLE IF NOT EXISTS query_cache (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
        state_name TEXT,
        fin_year TEXT,
        offset_value INTEGER DEFAULT 0,
        limit_value INTEGER DEFAULT 0,
        response JSONB NOT NULL,
        hits INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT now(),
        last_used TIMESTAMPTZ DEFAULT now()
      )`);
      await db.query(`CREATE INDEX IF NOT EXISTS query_cache_user_idx ON query_cache(user_id)`);
      await db.query(`CREATE INDEX IF NOT EXISTS query_cache_lookup_idx ON query_cache(user_id, state_name, fin_year, offset_value, limit_value)`);
      console.log('Query cache table checked/created');
    } catch (err) {
      console.error('Error ensuring users table exists', err.message || err);
    }
  })();
} else {
  console.warn('DATABASE_URL not set. Auth endpoints will return 500 until configured.');
}

// Proxy endpoint to query data.gov.in using API key from .env
// Accepts: offset, limit, filters[state_name], filters[fin_year]
// Helper to build the final data.gov.in URL from provided params
function buildTargetUrl(params) {
  console.log('Received params:', params);
  
  // Initialize URLSearchParams
  const urlParams = new URLSearchParams();
  
  // Add required parameters
  urlParams.set('api-key', API_KEY);
  urlParams.set('format', 'json');
  
  // Add offset and limit
  const offset = parseInt(params.offset) || 0;
  const limit = parseInt(params.limit) || 10;
  urlParams.set('offset', offset.toString());
  urlParams.set('limit', limit.toString());
  
  // Handle filters
  if (params.filters) {
    // If filters object is provided
    if (params.filters.state_name) {
      urlParams.set('filters[state_name]', params.filters.state_name.toUpperCase());
    }
    if (params.filters.fin_year) {
      urlParams.set('filters[fin_year]', params.filters.fin_year);
    }
  } else {
    // Legacy support for direct parameters
    if (params.state_name) {
      urlParams.set('filters[state_name]', params.state_name.toUpperCase());
    }
    if (params.fin_year) {
      urlParams.set('filters[fin_year]', params.fin_year);
    }
  }
  
  const url = `${API_BASE}?${urlParams.toString()}`;
  console.log('Generated URL:', url);
  return url;
}

function getUserIdFromReq(req) {
  try {
    const auth = req.headers && req.headers.authorization;
    if (!auth) {
      console.debug('No Authorization header');
      return null;
    }
    if (!auth.startsWith('Bearer ')) {
      console.debug('Not a Bearer token');
      return null;
    }
    const token = auth.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || !decoded.userId) {
      console.debug('Token invalid or missing userId:', decoded);
      return null;
    }
    console.debug('Valid token for userId:', decoded.userId);
    return decoded.userId;
  } catch (err) {
    console.debug('Token validation error:', err.message);
    return null;
  }
}

app.get('/api/data', async (req, res) => {
  const startTime = Date.now();
  try {
    if (!API_KEY) {
      return res.status(500).json({ error: 'API key not configured on server. Create a .env with API_KEY.' });
    }

    console.log('Received query params:', req.query);
    
    // Read and validate query params
    const offset = req.query.offset || req.query['filters[offset]'] || 0;
    const limit = req.query.limit || req.query['filters[limit]'] || 10;
    const state_name = req.query['filters[state_name]'] || req.query.state_name || req.query.state || '';
    const fin_year = req.query['filters[fin_year]'] || req.query.fin_year || '';

    // If user is authenticated, try returning cached result
    const userId = getUserIdFromReq(req);
    console.debug('GET /api/data - userId:', userId, 'limit:', limit);
    if (db && userId && limit) {
      try {
        console.debug('Checking cache for:', { userId, state_name, fin_year, offset, limit });
        const cached = await db.query(
          `SELECT id, response FROM query_cache WHERE user_id=$1 AND coalesce(state_name, '')=$2 AND coalesce(fin_year, '')=$3 AND coalesce(offset_value,0)=$4 AND coalesce(limit_value,0)=$5 ORDER BY created_at DESC LIMIT 1`,
          [userId, state_name || '', fin_year || '', Number(offset) || 0, Number(limit) || 0]
        );
        if (cached.rowCount > 0) {
          const row = cached.rows[0];
          console.debug('Cache hit for id:', row.id);
          db.query('UPDATE query_cache SET hits = hits + 1, last_used = now() WHERE id=$1', [row.id]).catch(() => {});
          return res.json(row.response);
        }
        console.debug('No cache entry found');
      } catch (err) {
        console.warn('Cache lookup failed', err && err.message);
      }
    }

    const target = buildTargetUrl({ offset, limit, state_name, fin_year });
    console.debug('Fetching from upstream:', target);

    // Use global fetch (Node 18+). If not available in user's Node, they can upgrade or we can add node-fetch.
    const r = await fetch(target);
    if (!r.ok) {
      const text = await r.text();
      return res.status(r.status).json({ error: `Upstream error: ${r.status}`, details: text });
    }
    const j = await r.json();

    // Store in cache if applicable (authenticated user and limit <= 100)
    const limitNum = Number(limit) || 0;
    if (db && userId && limitNum > 0 && limitNum <= 100) {
      try {
        console.debug('Storing in cache for user:', userId, 'with limit:', limitNum);
        await db.query(
          `INSERT INTO query_cache (user_id, state_name, fin_year, offset_value, limit_value, response) VALUES ($1,$2,$3,$4,$5,$6)`,
          [userId, state_name || null, fin_year || null, Number(offset) || 0, limitNum, j]
        );
        console.debug('Successfully stored in cache');
      } catch (err) {
        console.warn('Failed to write cache', err && err.message);
      }
    }

    // Forward the response as-is
    console.log(`Response time for ${req.method} ${req.path}: ${Date.now() - startTime}ms`);
    res.json(j);
  } catch (err) {
    console.error('Error in /api/data', err);
    res.status(500).json({ error: 'Internal server error', details: String(err) });
  }
});

// POST proxy - reads parameters from JSON body (preferred)
app.post('/api/data', async (req, res) => {
  const startTime = Date.now();
  try {
    if (!API_KEY) {
      return res.status(500).json({ error: 'API key not configured on server. Create a .env with API_KEY.' });
    }

    console.log('Received request body:', req.body);
    console.log('Request started at:', new Date(startTime).toISOString());

    // Parse and validate request parameters
    const params = {
      offset: req.body.offset || req.body.filters?.offset || 0,
      limit: req.body.limit || req.body.filters?.limit || 10,
      state_name: req.body.state_name || req.body.filters?.state_name || '',
      fin_year: req.body.fin_year || req.body.filters?.fin_year || ''
    };

    console.log('Parsed parameters:', params);

    // If user is authenticated, try returning cached result
    const userId = getUserIdFromReq(req);
    console.debug('POST /api/data - userId:', userId, 'limit:', params.limit);

    if (db && userId && params.limit) {
      try {
        console.debug('Checking cache for:', { userId, ...params });
        const cached = await db.query(
          `SELECT id, response FROM query_cache WHERE user_id=$1 AND coalesce(state_name, '')=$2 AND coalesce(fin_year, '')=$3 AND coalesce(offset_value,0)=$4 AND coalesce(limit_value,0)=$5 ORDER BY created_at DESC LIMIT 1`,
          [userId, params.state_name || '', params.fin_year || '', Number(params.offset) || 0, Number(params.limit) || 0]
        );
        if (cached.rowCount > 0) {
          const row = cached.rows[0];
          console.debug('Cache hit for id:', row.id);
          db.query('UPDATE query_cache SET hits = hits + 1, last_used = now() WHERE id=$1', [row.id]).catch(() => {});
          return res.json(row.response);
        }
        console.debug('No cache entry found');
      } catch (err) {
        console.warn('Cache lookup failed', err && err.message);
      }
    }

    const apiUrl = buildTargetUrl(params);
    console.debug('Fetching from API:', apiUrl);

    const r = await fetch(apiUrl);
    if (!r.ok) {
      const text = await r.text();
      console.error('API Error:', text);
      return res.status(r.status).json({ error: `Upstream error: ${r.status}`, details: text });
    }

    const j = await r.json();

    // Store in cache if applicable (authenticated user and limit <= 100)
    const limitNum = Number(params.limit) || 0;
    if (db && userId && limitNum > 0 && limitNum <= 100) {
      try {
        console.debug('Storing in cache for user:', userId, 'with limit:', limitNum);
        await db.query(
          `INSERT INTO query_cache (user_id, state_name, fin_year, offset_value, limit_value, response) VALUES ($1,$2,$3,$4,$5,$6)`,
          [userId, params.state_name || null, params.fin_year || null, Number(params.offset) || 0, limitNum, j]
        );
        console.debug('Successfully stored in cache');
      } catch (err) {
        console.warn('Failed to write cache', err && err.message, err.stack);
      }
    }

    console.log('Sending response with record count:', j.records?.length || 0);
    console.log(`Response time for ${req.method} ${req.path}: ${Date.now() - startTime}ms`);
    res.json(j);
  } catch (err) {
    console.error('Error in POST /api/data', err);
    res.status(500).json({ error: 'Internal server error', details: String(err) });
  }
});

// --- Authentication endpoints ---
// Register: { name, email, password }
app.post('/auth/register', async (req, res) => {
  const startTime = Date.now();
  try {
    if (!db) return res.status(500).json({ error: 'Database not configured' });
    const { name, email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    // check existing
    const exists = await db.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (exists.rowCount > 0) return res.status(409).json({ error: 'User already exists' });

    const hash = await bcrypt.hash(password, 10);
    const insert = await db.query('INSERT INTO users (email, password_hash, name) VALUES ($1,$2,$3) RETURNING id,email,name,created_at', [email.toLowerCase(), hash, name || null]);
    const user = insert.rows[0];
    // create token
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    console.log(`Response time for ${req.method} ${req.path}: ${Date.now() - startTime}ms`);
    res.json({ user: { id: user.id, email: user.email, name: user.name }, token });
  } catch (err) {
    console.error('Error in /auth/register', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login: { email, password }
app.post('/auth/login', async (req, res) => {
  const startTime = Date.now();
  try {
    if (!db) return res.status(500).json({ error: 'Database not configured' });
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const q = await db.query('SELECT id,email,password_hash,name,created_at FROM users WHERE email=$1', [email.toLowerCase()]);
    if (q.rowCount === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = q.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    console.log(`Response time for ${req.method} ${req.path}: ${Date.now() - startTime}ms`);
    res.json({ user: { id: user.id, email: user.email, name: user.name }, token });
  } catch (err) {
    console.error('Error in /auth/login', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get query history for the authenticated user
app.get('/api/history', async (req, res) => {
  const startTime = Date.now();
  try {
    const userId = getUserIdFromReq(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const query = `
      SELECT
        id,
        state_name,
        fin_year,
        offset_value,
        limit_value,
        created_at,
        hits,
        last_used
      FROM query_cache
      WHERE user_id = $1
      ORDER BY last_used DESC
      LIMIT 100
    `;

    const result = await db.query(query, [userId]);
    console.log(`Response time for ${req.method} ${req.path}: ${Date.now() - startTime}ms`);
    res.json(result.rows);
  } catch (err) {
    console.error('Error in /api/history', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current user info from Bearer token
app.get('/auth/me', async (req, res) => {
  const startTime = Date.now();
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
    const token = auth.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!db) return res.status(500).json({ error: 'Database not configured' });
    const q = await db.query('SELECT id,email,name,created_at FROM users WHERE id=$1', [decoded.userId]);
    if (q.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    console.log(`Response time for ${req.method} ${req.path}: ${Date.now() - startTime}ms`);
    res.json({ user: q.rows[0] });
  } catch (err) {
    console.error('Error in /auth/me', err);
    res.status(401).json({ error: 'Invalid token' });
  }
});
function loadData() {
  const raw = fs.readFileSync(DATA_FILE, 'utf8');
  const obj = JSON.parse(raw);
  return obj.records || [];
}

// Example: /api/performance?state=KARNATAKA&fin_year=2024-2025
app.get('/api/performance', (req, res) => {
  const { state, fin_year, month } = req.query;
  let records = loadData();
  if (state) {
    records = records.filter(r => r.state_name && r.state_name.toLowerCase() === state.toLowerCase());
  }
  if (fin_year) {
    records = records.filter(r => r.fin_year && r.fin_year.toLowerCase() === fin_year.toLowerCase());
  }
  if (month) {
    records = records.filter(r => r.month && r.month.toLowerCase() === month.toLowerCase());
  }
  res.json({ count: records.length, records });
});

// Endpoint to get all available states
app.get('/api/states', async (req, res) => {
  const startTime = Date.now();
  try {
    // Fetch initial data to get states
    const response = await fetch(`${API_BASE}?api-key=${API_KEY}&format=json&limit=1000`);
    if (!response.ok) {
      return res.status(response.status).json({ error: 'Failed to fetch states' });
    }

    const data = await response.json();
    if (!data.records) {
      return res.status(500).json({ error: 'No records found' });
    }

    // Extract unique states
    const states = [...new Set(data.records
      .map(record => record.state_name)
      .filter(state => state) // Remove null/undefined
      .sort()
    )];

    console.log(`Response time for ${req.method} ${req.path}: ${Date.now() - startTime}ms`);
    res.json({ states });
  } catch (err) {
    console.error('Error fetching states:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to get districts for a state
app.get('/api/districts/:state', async (req, res) => {
  const startTime = Date.now();
  try {
    const state = req.params.state;
    const response = await fetch(`${API_BASE}?api-key=${API_KEY}&format=json&limit=1000&filters[state_name]=${encodeURIComponent(state)}`);

    if (!response.ok) {
      return res.status(response.status).json({ error: 'Failed to fetch districts' });
    }

    const data = await response.json();
    if (!data.records) {
      return res.status(500).json({ error: 'No records found' });
    }

    // Extract unique districts
    const districts = [...new Set(data.records
      .map(record => record.district_name)
      .filter(district => district) // Remove null/undefined
      .sort()
    )];

    console.log(`Response time for ${req.method} ${req.path}: ${Date.now() - startTime}ms`);
    res.json({ districts });
  } catch (err) {
    console.error('Error fetching districts:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`branch : rmlimit`);
});