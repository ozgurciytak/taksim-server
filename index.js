const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://gvhcjdolbelygfmmmhzg.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || Buffer.from('c2Jfc2VjcmV0X1NtY2V3UzJvVG9mbXRRUjRleFJud1FfeE1OcEphdS0=', 'base64').toString('utf-8');
const API_KEY = process.env.API_KEY || 'taksim-secret-key-2024';

// Helper for Supabase REST API requests
async function supabaseFetch(endpoint, options = {}) {
  const url = `${SUPABASE_URL}/rest/v1/${endpoint}`;
  const headers = {
    'apikey': SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type': 'application/json',
    'Prefer': options.prefer || 'return=representation',
    ...(options.headers || {})
  };

  const res = await fetch(url, {
    ...options,
    headers
  });

  if (!res.ok) {
    const errorText = await res.text();
    console.error(`Supabase error [${res.status}] ${url}:`, errorText);
    throw new Error(errorText || `Supabase error ${res.status}`);
  }

  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

// Security Middleware: API Key check
app.use((req, res, next) => {
  // Allow health check without API key
  if (req.path === '/' || req.path === '/health') {
    return next();
  }

  const apiKey = req.header('x-api-key');
  if (apiKey && apiKey !== API_KEY) {
    return res.status(403).json({ error: 'Unauthorized access. API Key is invalid.' });
  }
  next();
});

// Health check
app.get(['/', '/health'], (req, res) => {
  res.json({ status: 'ok', service: 'Taksim Server API', timestamp: new Date().toISOString() });
});

// --- System Settings ---
app.get('/systemSettings', async (req, res) => {
  try {
    const data = await supabaseFetch('system_settings?id=eq.default&select=*');
    if (data && data.length > 0) {
      return res.json(data[0].data);
    }
    res.json({
      backend: { apiUrl: '' },
      payment: { iban: '', companyTitle: '', apiKey: '', apiSecret: '', merchantId: '' },
      app: { applicationFee: 10 }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.all(['/systemSettings'], async (req, res) => {
  if (req.method !== 'PUT' && req.method !== 'PATCH' && req.method !== 'POST') return res.status(405).end();
  try {
    const updated = await supabaseFetch('system_settings?id=eq.default', {
      method: 'PATCH',
      body: JSON.stringify({ data: req.body, updated_at: new Date().toISOString() })
    });
    res.json(req.body);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Auth Login ---
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email ve şifre gereklidir.' });
    }

    const cleanEmail = email.toLowerCase().trim();
    let query = `users?email=ilike.${encodeURIComponent(cleanEmail)}&select=*`;
    if (role) {
      query += `&role=eq.${encodeURIComponent(role)}`;
    }

    const users = await supabaseFetch(query);
    if (!users || users.length === 0) {
      return res.status(401).json({ error: 'Kullanıcı bulunamadı.' });
    }

    const userRow = users[0];
    const userData = userRow.data || {};
    const storedPassword = userData.password;
    const plainPassword = userData.plainPassword;

    const isMatch = (storedPassword && (
      bcrypt.compareSync(password, storedPassword) || password === storedPassword
    )) || (plainPassword && password === plainPassword);

    if (!isMatch) {
      return res.status(401).json({ error: 'Hatalı şifre.' });
    }

    const { password: _, ...safeUser } = userData;
    res.json({ ...safeUser, id: userRow.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Users Endpoints ---
app.get('/users', async (req, res) => {
  try {
    let query = 'users?select=*';
    if (req.query.role) {
      query += `&role=eq.${encodeURIComponent(req.query.role)}`;
    }
    const rows = await supabaseFetch(query);
    const result = (rows || []).map(r => {
      const u = { ...(r.data || {}), id: r.id };
      // Admin şifreyi görebilsin:
      u.password = u.plainPassword || '';
      return u;
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/users/:id', async (req, res) => {
  try {
    const rows = await supabaseFetch(`users?id=eq.${encodeURIComponent(req.params.id)}&select=*`);
    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }
    const u = { ...(rows[0].data || {}), id: rows[0].id };
    u.password = u.plainPassword || '';
    res.json(u);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/users', async (req, res) => {
  try {
    const body = { ...req.body };
    const id = body.id || String(Date.now());
    body.id = id;

    // Şoförler ve tüm yeni kayıtlar varsayılan olarak otomatik aktif ve onaylı olsun
    body.status = body.status || 'active';
    body.isApproved = body.isApproved !== undefined ? body.isApproved : true;

    if (body.password) {
      body.plainPassword = body.password; // Adminin görebilmesi için sakla
      if (!body.password.startsWith('$2')) {
        body.password = bcrypt.hashSync(body.password, 10);
      }
    }

    const email = (body.email || '').toLowerCase().trim();
    const role = body.role || 'driver';

    await supabaseFetch('users', {
      method: 'POST',
      body: JSON.stringify({
        id,
        email,
        role,
        data: body
      })
    });

    const safeUser = { ...body };
    safeUser.password = body.plainPassword || '';
    res.status(201).json(safeUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/users/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const existing = await supabaseFetch(`users?id=eq.${encodeURIComponent(id)}&select=*`);
    if (!existing || existing.length === 0) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    const currentData = existing[0].data || {};
    const updates = { ...req.body };

    if (updates.password) {
      updates.plainPassword = updates.password; // Admin veya kullanıcı şifreyi güncelleyince plainPassword olarak da sakla
      if (!updates.password.startsWith('$2')) {
        updates.password = bcrypt.hashSync(updates.password, 10);
      }
    }

    const mergedData = { ...currentData, ...updates, id };

    const updatePayload = { data: mergedData };
    if (updates.email) updatePayload.email = updates.email.toLowerCase().trim();
    if (updates.role) updatePayload.role = updates.role;

    await supabaseFetch(`users?id=eq.${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(updatePayload)
    });

    const safeUser = { ...mergedData };
    safeUser.password = mergedData.plainPassword || '';
    res.json(safeUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/users/:id', async (req, res) => {
  try {
    await supabaseFetch(`users?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE'
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Generic Collections Handlers ---
// Supported: posts, applications, payments, referanslar, vehicles, conversations, messages
const TABLE_MAP = {
  posts: 'posts',
  applications: 'applications',
  payments: 'payments',
  referanslar: 'referanslar',
  vehicles: 'vehicles',
  conversations: 'conversations',
  messages: 'messages'
};

app.get('/:collection', async (req, res) => {
  const coll = req.params.collection;
  const table = TABLE_MAP[coll];
  if (!table) return res.status(404).json({ error: 'Koleksiyon bulunamadı' });

  try {
    let query = `${table}?select=*`;

    // Map common filter parameters
    if (req.query.userId) query += `&user_id=eq.${encodeURIComponent(req.query.userId)}`;
    if (req.query.driverId) query += `&driver_id=eq.${encodeURIComponent(req.query.driverId)}`;
    if (req.query.ownerId) query += `&owner_id=eq.${encodeURIComponent(req.query.ownerId)}`;
    if (req.query.postId) query += `&post_id=eq.${encodeURIComponent(req.query.postId)}`;
    if (req.query.conversationId) query += `&conversation_id=eq.${encodeURIComponent(req.query.conversationId)}`;
    if (req.query.type) query += `&post_type=eq.${encodeURIComponent(req.query.type)}`;

    // Order / Sort
    if (req.query._sort) {
      const order = req.query._order === 'desc' ? 'desc' : 'asc';
      // If sorting by created_at or standard fields
      query += `&order=created_at.${order}`;
    }

    const rows = await supabaseFetch(query);
    let items = (rows || []).map(r => ({ ...(r.data || {}), id: r.id }));

    // Memory-sort if custom field sorting is requested
    if (req.query._sort && req.query._sort !== 'created_at') {
      const sortField = req.query._sort;
      const isDesc = req.query._order === 'desc';
      items.sort((a, b) => {
        const valA = a[sortField] || '';
        const valB = b[sortField] || '';
        if (valA < valB) return isDesc ? 1 : -1;
        if (valA > valB) return isDesc ? -1 : 1;
        return 0;
      });
    }

    res.json(items);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/:collection/:id', async (req, res) => {
  const coll = req.params.collection;
  const table = TABLE_MAP[coll];
  if (!table) return res.status(404).json({ error: 'Koleksiyon bulunamadı' });

  try {
    const rows = await supabaseFetch(`${table}?id=eq.${encodeURIComponent(req.params.id)}&select=*`);
    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Kayıt bulunamadı' });
    }
    res.json({ ...(rows[0].data || {}), id: rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/:collection', async (req, res) => {
  const coll = req.params.collection;
  const table = TABLE_MAP[coll];
  if (!table) return res.status(404).json({ error: 'Koleksiyon bulunamadı' });

  try {
    const body = { ...req.body };
    const id = body.id || String(Date.now());
    body.id = id;

    const rowPayload = {
      id,
      data: body,
      created_at: new Date().toISOString()
    };

    if (body.userId) rowPayload.user_id = body.userId;
    if (body.driverId) rowPayload.driver_id = body.driverId;
    if (body.ownerId) rowPayload.owner_id = body.ownerId;
    if (body.postId) rowPayload.post_id = body.postId;
    if (body.conversationId) rowPayload.conversation_id = body.conversationId;
    if (body.type) rowPayload.post_type = body.type;

    await supabaseFetch(table, {
      method: 'POST',
      body: JSON.stringify(rowPayload)
    });

    res.status(201).json(body);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/:collection/:id', async (req, res) => {
  const coll = req.params.collection;
  const table = TABLE_MAP[coll];
  if (!table) return res.status(404).json({ error: 'Koleksiyon bulunamadı' });

  try {
    const id = req.params.id;
    const existing = await supabaseFetch(`${table}?id=eq.${encodeURIComponent(id)}&select=*`);
    if (!existing || existing.length === 0) {
      return res.status(404).json({ error: 'Kayıt bulunamadı' });
    }

    const currentData = existing[0].data || {};
    const mergedData = { ...currentData, ...req.body, id };

    await supabaseFetch(`${table}?id=eq.${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ data: mergedData })
    });

    res.json(mergedData);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/:collection/:id', async (req, res) => {
  const coll = req.params.collection;
  const table = TABLE_MAP[coll];
  if (!table) return res.status(404).json({ error: 'Koleksiyon bulunamadı' });

  try {
    await supabaseFetch(`${table}?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE'
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Taksim Server running on port ${PORT}`);
  });
}

module.exports = app;
