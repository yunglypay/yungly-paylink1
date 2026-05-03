const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const bcrypt  = require('bcrypt');
const path    = require('path');
const { pool, initDB } = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

const frontendPath = path.join(__dirname, 'public');
app.use(express.static(frontendPath));

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function uid(prefix) { return prefix + '_' + crypto.randomBytes(5).toString('hex'); }
function token()     { return crypto.randomBytes(32).toString('hex'); }

function mapUser(u) {
  return {
    id: u.id, name: u.name, displayName: u.display_name, handle: u.handle,
    phone: u.phone, role: u.role, parentId: u.parent_id,
    walletBalance: u.wallet_balance, monthlyReceived: u.monthly_received,
    monthlyLimit: u.monthly_limit, kycVerified: u.kyc_verified,
    guardianApproved: u.guardian_approved, createdAt: u.created_at
  };
}
function mapParent(p) {
  return {
    id: p.id, name: p.name, phone: p.phone, teenId: p.teen_id, teenPhone: p.teen_phone,
    role: 'parent', createdAt: p.created_at,
    settings: {
      perLinkLimit: p.per_link_limit, dailyLimit: p.daily_limit,
      monthlyLimit: p.monthly_limit, blockedCategories: p.blocked_categories
    }
  };
}
function mapLink(r) {
  return {
    id: r.id, creatorId: r.creator_id, displayName: r.display_name, handle: r.handle,
    amount: r.amount, purpose: r.purpose, note: r.note, status: r.status,
    txnId: r.txn_id, expiresAt: r.expires_at, createdAt: r.created_at
  };
}
function mapTxn(r) {
  return {
    id: r.id, linkId: r.link_id, amount: r.amount, purpose: r.purpose,
    from: r.from_name, to: r.to_user, paymentMethod: r.payment_method,
    status: r.status, createdAt: r.created_at
  };
}

// Auth middleware
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const tok = auth.slice(7);
  const { rows } = await pool.query(
    `SELECT * FROM sessions WHERE token = $1 AND expires_at > NOW()`, [tok]
  );
  if (!rows[0]) return res.status(401).json({ error: 'Session expired. Please login again.' });
  req.session = rows[0];
  next();
}

// ─── REGISTER ─────────────────────────────────────────────────────────────────

// Teen registration
app.post('/api/auth/register/teen', async (req, res) => {
  try {
    const { name, displayName, handle, phone, password, parentPhone } = req.body;

    if (!name || !phone || !password || !displayName || !handle)
      return res.status(400).json({ error: 'All fields are required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    // Check phone/handle unique
    const { rows: existing } = await pool.query(
      `SELECT id FROM users WHERE phone = $1 OR handle = $2`, [phone, handle]
    );
    if (existing.length > 0)
      return res.status(400).json({ error: 'Phone number or handle already registered' });

    // Find parent if parentPhone provided
    let parentId = null;
    if (parentPhone) {
      const { rows: parents } = await pool.query(
        `SELECT id FROM parents WHERE phone = $1`, [parentPhone]
      );
      if (parents[0]) {
        parentId = parents[0].id;
        // Link parent to this teen
        await pool.query(
          `UPDATE parents SET teen_id = $1, teen_phone = $2 WHERE id = $3`,
          [uid('temp'), phone, parentId]
        );
      }
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const id = uid('u');
    const cleanHandle = handle.startsWith('@') ? handle : '@' + handle;

    await pool.query(
      `INSERT INTO users (id, name, display_name, handle, phone, password_hash, role, parent_id, monthly_limit, kyc_verified, guardian_approved)
       VALUES ($1,$2,$3,$4,$5,$6,'teen',$7,5000,false,$8)`,
      [id, name, displayName, cleanHandle, phone, passwordHash, parentId, parentId ? true : false]
    );

    // Update parent's teen_id to real id
    if (parentId) {
      await pool.query(`UPDATE parents SET teen_id = $1 WHERE id = $2`, [id, parentId]);
    }

    // Create session (30 days)
    const tok = token();
    await pool.query(
      `INSERT INTO sessions (token, user_id, role, expires_at) VALUES ($1,$2,'teen', NOW() + INTERVAL '30 days')`,
      [tok, id]
    );

    const { rows: users } = await pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
    res.status(201).json({ token: tok, user: mapUser(users[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error: ' + e.message });
  }
});

// Parent registration
app.post('/api/auth/register/parent', async (req, res) => {
  try {
    const { name, phone, password, teenPhone } = req.body;

    if (!name || !phone || !password)
      return res.status(400).json({ error: 'Name, phone and password are required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const { rows: existing } = await pool.query(`SELECT id FROM parents WHERE phone = $1`, [phone]);
    if (existing.length > 0)
      return res.status(400).json({ error: 'Phone number already registered' });

    // Find teen if teenPhone provided
    let teenId = null;
    if (teenPhone) {
      const { rows: teens } = await pool.query(`SELECT id FROM users WHERE phone = $1`, [teenPhone]);
      if (teens[0]) teenId = teens[0].id;
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const id = uid('p');

    await pool.query(
      `INSERT INTO parents (id, name, phone, password_hash, teen_id, teen_phone) VALUES ($1,$2,$3,$4,$5,$6)`,
      [id, name, phone, passwordHash, teenId, teenPhone || null]
    );

    // Link teen to this parent
    if (teenId) {
      await pool.query(`UPDATE users SET parent_id = $1, guardian_approved = true WHERE id = $2`, [id, teenId]);
    }

    const tok = token();
    await pool.query(
      `INSERT INTO sessions (token, user_id, role, expires_at) VALUES ($1,$2,'parent', NOW() + INTERVAL '30 days')`,
      [tok, id]
    );

    const { rows: parents } = await pool.query(`SELECT * FROM parents WHERE id = $1`, [id]);
    res.status(201).json({ token: tok, user: mapParent(parents[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error: ' + e.message });
  }
});

// ─── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password, role } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'Phone and password required' });

    if (role === 'admin') {
      const { rows } = await pool.query(`SELECT * FROM users WHERE role = 'admin' AND phone = $1`, [phone]);
      if (!rows[0]) return res.status(401).json({ error: 'Invalid credentials' });
      const match = await bcrypt.compare(password, rows[0].password_hash);
      if (!match) return res.status(401).json({ error: 'Invalid credentials' });
      const tok = token();
      await pool.query(
        `INSERT INTO sessions (token, user_id, role, expires_at) VALUES ($1,$2,'admin', NOW() + INTERVAL '7 days')`,
        [tok, rows[0].id]
      );
      return res.json({ token: tok, user: mapUser(rows[0]) });
    }

    if (role === 'parent') {
      const { rows } = await pool.query(`SELECT * FROM parents WHERE phone = $1`, [phone]);
      if (!rows[0]) return res.status(401).json({ error: 'No account found with this phone number' });
      const match = await bcrypt.compare(password, rows[0].password_hash);
      if (!match) return res.status(401).json({ error: 'Wrong password' });
      const tok = token();
      await pool.query(
        `INSERT INTO sessions (token, user_id, role, expires_at) VALUES ($1,$2,'parent', NOW() + INTERVAL '30 days')`,
        [tok, rows[0].id]
      );
      return res.json({ token: tok, user: mapParent(rows[0]) });
    }

    // teen
    const { rows } = await pool.query(`SELECT * FROM users WHERE phone = $1 AND role = 'teen'`, [phone]);
    if (!rows[0]) return res.status(401).json({ error: 'No account found with this phone number' });
    const match = await bcrypt.compare(password, rows[0].password_hash);
    if (!match) return res.status(401).json({ error: 'Wrong password' });
    const tok = token();
    await pool.query(
      `INSERT INTO sessions (token, user_id, role, expires_at) VALUES ($1,$2,'teen', NOW() + INTERVAL '30 days')`,
      [tok, rows[0].id]
    );
    return res.json({ token: tok, user: mapUser(rows[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  await pool.query(`DELETE FROM sessions WHERE token = $1`, [req.headers.authorization.slice(7)]);
  res.json({ ok: true });
});

// Get current user (for auto-login on revisit)
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const { user_id, role } = req.session;
    if (role === 'parent') {
      const { rows } = await pool.query(`SELECT * FROM parents WHERE id = $1`, [user_id]);
      if (!rows[0]) return res.status(404).json({ error: 'Not found' });
      return res.json({ user: mapParent(rows[0]) });
    }
    const { rows } = await pool.query(`SELECT * FROM users WHERE id = $1`, [user_id]);
    if (!rows[0]) return res.status(404).json({ error: 'Not found' });
    res.json({ user: mapUser(rows[0]) });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── PAYLINKS ─────────────────────────────────────────────────────────────────
app.post('/api/paylinks', requireAuth, async (req, res) => {
  try {
    const { amount, purpose, note, expiryDays } = req.body;
    const creatorId = req.session.user_id;

    const { rows: users } = await pool.query(`SELECT * FROM users WHERE id = $1`, [creatorId]);
    if (!users[0]) return res.status(404).json({ error: 'User not found' });
    const user = users[0];

    if (user.parent_id) {
      const { rows: parents } = await pool.query(`SELECT * FROM parents WHERE id = $1`, [user.parent_id]);
      if (parents[0] && amount > parents[0].per_link_limit)
        return res.status(400).json({ error: `Amount exceeds per-link limit of ₹${parents[0].per_link_limit}` });
    }

    const id = uid('lnk');
    const expiresAt = new Date(Date.now() + (expiryDays || 7) * 86400000);

    await pool.query(
      `INSERT INTO paylinks (id, creator_id, display_name, handle, amount, purpose, note, status, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8)`,
      [id, creatorId, user.display_name, user.handle, Number(amount), purpose, note || '', expiresAt]
    );

    const link = { id, creatorId, displayName: user.display_name, handle: user.handle, amount: Number(amount), purpose, note, status: 'active', expiresAt };
    res.json({ link, payUrl: `https://${req.get('host')}/pay/${id}` });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/paylinks', requireAuth, async (req, res) => {
  try {
    const creatorId = req.session.user_id;
    const { rows } = await pool.query(
      `SELECT * FROM paylinks WHERE creator_id = $1 ORDER BY created_at DESC`, [creatorId]
    );
    res.json(rows.map(mapLink));
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/paylinks/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM paylinks WHERE id = $1`, [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Link not found' });
    const link = mapLink(rows[0]);
    const { rows: users } = await pool.query(`SELECT * FROM users WHERE id = $1`, [link.creatorId]);
    const creator = users[0];
    res.json({ link, creator: { displayName: creator?.display_name, handle: creator?.handle, kycVerified: creator?.kyc_verified } });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/paylinks/:id', requireAuth, async (req, res) => {
  try {
    await pool.query(`UPDATE paylinks SET status = 'cancelled' WHERE id = $1 AND creator_id = $2`,
      [req.params.id, req.session.user_id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── PAYMENT (public — no auth needed) ────────────────────────────────────────
app.post('/api/pay/:linkId/initiate', async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM paylinks WHERE id = $1`, [req.params.linkId]);
    if (!rows[0]) return res.status(404).json({ error: 'Link not found' });
    const link = mapLink(rows[0]);
    if (link.status !== 'active') return res.status(400).json({ error: 'This link is ' + link.status });
    if (new Date(link.expiresAt) < new Date()) return res.status(400).json({ error: 'Link has expired' });

    res.json({
      orderId: 'order_' + crypto.randomBytes(6).toString('hex'),
      amount: link.amount * 100,
      currency: 'INR',
      key: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder',
      name: 'Yungly Pay',
      description: link.purpose,
      prefill: { name: req.body.customerName || '' }
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/pay/:linkId/confirm', async (req, res) => {
  try {
    const { rows: linkRows } = await pool.query(`SELECT * FROM paylinks WHERE id = $1`, [req.params.linkId]);
    if (!linkRows[0]) return res.status(404).json({ error: 'Link not found' });
    const link = mapLink(linkRows[0]);
    const { customerName, paymentMethod, razorpayPaymentId } = req.body;
    const txnId = uid('txn');

    await pool.query(
      `INSERT INTO transactions (id, link_id, amount, purpose, from_name, to_user, payment_method, razorpay_payment_id, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'success')`,
      [txnId, link.id, link.amount, link.purpose, customerName || 'Customer',
       link.creatorId, paymentMethod || 'UPI', razorpayPaymentId || 'pay_mock_' + Date.now()]
    );

    await pool.query(`UPDATE paylinks SET status = 'paid', txn_id = $1 WHERE id = $2`, [txnId, link.id]);
    await pool.query(
      `UPDATE users SET wallet_balance = wallet_balance + $1, monthly_received = monthly_received + $1 WHERE id = $2`,
      [link.amount, link.creatorId]
    );

    const { rows: users } = await pool.query(`SELECT * FROM users WHERE id = $1`, [link.creatorId]);
    const creator = users[0];

    if (creator?.parent_id) {
      await pool.query(
        `INSERT INTO notifications (id, parent_id, type, message, txn_id, amount, read)
         VALUES ($1,$2,'payment_received',$3,$4,$5,false)`,
        [uid('notif'), creator.parent_id,
         `${creator.display_name} received ₹${link.amount} for "${link.purpose}" from ${customerName || 'Customer'}`,
         txnId, link.amount]
      );
    }

    res.json({
      txn: { id: txnId, amount: link.amount, purpose: link.purpose, from: customerName, status: 'success' },
      receipt: { txnId, amount: link.amount, purpose: link.purpose, from: customerName || 'Customer', to: creator?.display_name || 'Creator', date: new Date().toISOString() }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── TRANSACTIONS ─────────────────────────────────────────────────────────────
app.get('/api/transactions', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM transactions WHERE to_user = $1 ORDER BY created_at DESC`,
      [req.session.user_id]
    );
    res.json(rows.map(mapTxn));
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── PARENT ───────────────────────────────────────────────────────────────────
app.get('/api/parent/me', requireAuth, async (req, res) => {
  try {
    const { rows: parents } = await pool.query(`SELECT * FROM parents WHERE id = $1`, [req.session.user_id]);
    if (!parents[0]) return res.status(404).json({ error: 'Not found' });
    const parent = parents[0];

    const { rows: teens } = await pool.query(`SELECT * FROM users WHERE id = $1`, [parent.teen_id]);
    const { rows: notifs } = await pool.query(
      `SELECT * FROM notifications WHERE parent_id = $1 ORDER BY created_at DESC`, [parent.id]
    );

    const teen = teens[0];
    res.json({
      parent: {
        ...mapParent(parent),
        notifications: notifs.map(n => ({ id: n.id, type: n.type, message: n.message, txnId: n.txn_id, amount: n.amount, read: n.read, createdAt: n.created_at }))
      },
      teen: teen ? mapUser(teen) : null
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/parent/me/settings', requireAuth, async (req, res) => {
  try {
    const { perLinkLimit, dailyLimit, monthlyLimit } = req.body;
    await pool.query(
      `UPDATE parents SET
        per_link_limit = COALESCE($1, per_link_limit),
        daily_limit = COALESCE($2, daily_limit),
        monthly_limit = COALESCE($3, monthly_limit)
       WHERE id = $4`,
      [perLinkLimit, dailyLimit, monthlyLimit, req.session.user_id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/parent/me/notifications/read', requireAuth, async (req, res) => {
  try {
    await pool.query(`UPDATE notifications SET read = true WHERE parent_id = $1`, [req.session.user_id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Link parent to teen after the fact
app.post('/api/parent/me/link-teen', requireAuth, async (req, res) => {
  try {
    const { teenPhone } = req.body;
    const { rows: teens } = await pool.query(`SELECT * FROM users WHERE phone = $1 AND role = 'teen'`, [teenPhone]);
    if (!teens[0]) return res.status(404).json({ error: 'No teen account found with that phone number' });
    const teen = teens[0];
    await pool.query(`UPDATE parents SET teen_id = $1, teen_phone = $2 WHERE id = $3`,
      [teen.id, teenPhone, req.session.user_id]);
    await pool.query(`UPDATE users SET parent_id = $1, guardian_approved = true WHERE id = $2`,
      [req.session.user_id, teen.id]);
    res.json({ ok: true, teen: mapUser(teen) });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── ADMIN ────────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const [{ rows: txns }, { rows: links }, { rows: users }] = await Promise.all([
      pool.query(`SELECT * FROM transactions ORDER BY created_at DESC`),
      pool.query(`SELECT * FROM paylinks ORDER BY created_at DESC`),
      pool.query(`SELECT * FROM users WHERE role = 'teen'`)
    ]);
    const successTxns = txns.filter(t => t.status === 'success');
    res.json({
      totalUsers: users.length,
      totalLinks: links.length,
      activeLinks: links.filter(l => l.status === 'active').length,
      totalTxns: txns.length,
      totalVolume: successTxns.reduce((s, t) => s + t.amount, 0),
      successRate: txns.length ? Math.round(successTxns.length / txns.length * 100) : 0,
      recentTxns: txns.slice(0, 10).map(mapTxn)
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/users', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const { rows } = await pool.query(`SELECT * FROM users WHERE role = 'teen' ORDER BY created_at DESC`);
    res.json(rows.map(mapUser));
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/transactions', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const { rows } = await pool.query(`SELECT * FROM transactions ORDER BY created_at DESC`);
    res.json(rows.map(mapTxn));
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── SERVE SPA ────────────────────────────────────────────────────────────────
app.get('/pay/:id', (req, res) => res.sendFile(path.join(frontendPath, 'index.html')));
app.get('*',       (req, res) => res.sendFile(path.join(frontendPath, 'index.html')));

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
initDB()
  .then(() => app.listen(PORT, () => console.log(`🚀 Yungly PayLink on port ${PORT}`)))
  .catch(err => { console.error('Failed to init DB:', err); process.exit(1); });
