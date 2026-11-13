require('dotenv').config();
const express  = require('express');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const { rateLimit } = require('express-rate-limit');
const { randomUUID } = require('crypto');
const path = require('path');

const app            = express();
const PORT           = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ORGANISER_EMAIL = process.env.ORGANISER_EMAIL || '';
const SITE_URL       = (process.env.SITE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');

if (!ADMIN_PASSWORD) {
  console.error('ERROR: ADMIN_PASSWORD must be set in environment. See .env.example');
  process.exit(1);
}

// ── Database ──────────────────────────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS challenges (
      id                  TEXT PRIMARY KEY,
      title               TEXT NOT NULL,
      position_a          TEXT NOT NULL,
      position_b          TEXT NOT NULL,
      challenger_position TEXT NOT NULL CHECK(challenger_position IN ('A','B')),
      challenger_name     TEXT NOT NULL,
      challenger_email    TEXT NOT NULL,
      challenger_links    JSONB NOT NULL DEFAULT '[]',
      status              TEXT NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending','open','matched','closed','deleted')),
      verify_token        TEXT UNIQUE,
      verify_expires      TIMESTAMPTZ,
      created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS acceptances (
      id              TEXT PRIMARY KEY,
      challenge_id    TEXT NOT NULL UNIQUE,
      acceptor_name   TEXT NOT NULL,
      acceptor_email  TEXT NOT NULL,
      acceptor_links  JSONB NOT NULL DEFAULT '[]',
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pending_acceptances (
      id              TEXT PRIMARY KEY,
      challenge_id    TEXT NOT NULL UNIQUE,
      acceptor_name   TEXT NOT NULL,
      acceptor_email  TEXT NOT NULL,
      acceptor_links  JSONB NOT NULL DEFAULT '[]',
      verify_token    TEXT NOT NULL UNIQUE,
      verify_expires  TIMESTAMPTZ NOT NULL,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE pending_acceptances ADD COLUMN IF NOT EXISTS acceptor_position TEXT;

    CREATE TABLE IF NOT EXISTS verified_debaters (
      email        TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      added_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  console.log('Schema ready.');
}

// ── Cleanup expired tokens ────────────────────────────────────────────────────

async function cleanup() {
  await pool.query(`DELETE FROM pending_acceptances WHERE verify_expires < NOW()`);
}

setInterval(() => cleanup().catch(console.error), 5 * 60 * 1000);

// ── Admin sessions ────────────────────────────────────────────────────────────

const adminSessions = new Map(); // token → expiry ms

function createAdminSession() {
  const token = randomUUID();
  adminSessions.set(token, Date.now() + 24 * 60 * 60 * 1000);
  return token;
}

setInterval(() => {
  const now = Date.now();
  for (const [t, exp] of adminSessions) if (exp < now) adminSessions.delete(t);
}, 60 * 60 * 1000);

// ── Email ─────────────────────────────────────────────────────────────────────

const mailer = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

function sendMail(to, subject, text) {
  if (!mailer) {
    console.log('[EMAIL skipped — no SMTP configured]');
    console.log(`  To: ${to}\n  Subject: ${subject}\n  ---\n${text}\n`);
    return Promise.resolve();
  }
  return mailer
    .sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to, subject, text })
    .catch(err => console.error('Email failed:', err.message));
}

// ── Middleware ────────────────────────────────────────────────────────────────

app.set('trust proxy', 1);

app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] === 'http') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  res.set({
    'X-Content-Type-Options':  'nosniff',
    'X-Frame-Options':         'DENY',
    'Referrer-Policy':         'strict-origin-when-cross-origin',
    'Permissions-Policy':      'geolocation=(), camera=(), microphone=()',
  });
  next();
});

app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const submitLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many submissions from this IP. Please try again in an hour.' },
});

const reportLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many reports from this IP.' },
});

function requireAdmin(req, res, next) {
  // Accept session cookie (set after initial Basic Auth login)
  const cookieHeader = req.headers.cookie || '';
  const m = cookieHeader.match(/(?:^|;\s*)admin_session=([^;]+)/);
  if (m) {
    const exp = adminSessions.get(m[1]);
    if (exp && exp > Date.now()) return next();
  }

  // Fall back to Basic Auth
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) {
    return res.set('WWW-Authenticate', 'Basic realm="Mute Points Admin"').status(401).end('Unauthorized');
  }
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const colon   = decoded.indexOf(':');
  if (decoded.slice(0, colon) === 'paul.brook@gmail.com' && decoded.slice(colon + 1) === ADMIN_PASSWORD) return next();
  res.set('WWW-Authenticate', 'Basic realm="Mute Points Admin"').status(401).end('Unauthorized');
}

// ── Input sanitization ────────────────────────────────────────────────────────

function trimStr(str, max = 500) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g, '').trim().slice(0, max);
}

function parseEmail(str) {
  const s = trimStr(str, 254).toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) ? s : '';
}

function parseUrl(str) {
  const s = trimStr(str, 500);
  if (!s) return '';
  const prefixed = /^https?:\/\//i.test(s) ? s : `https://${s}`;
  try {
    const u = new URL(prefixed);
    return ['http:', 'https:'].includes(u.protocol) ? u.href : '';
  } catch { return ''; }
}

function parseLinks(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .slice(0, 3)
    .map(l => ({ label: trimStr(l?.label || '', 80), url: parseUrl(l?.url || '') }))
    .filter(l => l.url);
}

// Normalise links from DB — column may be TEXT or JSONB depending on when
// the table was first created (CREATE TABLE IF NOT EXISTS won't alter columns).
function normalizeLinks(raw) {
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string') { try { return JSON.parse(raw); } catch { return []; } }
  return [];
}

// ── Verification page helper ──────────────────────────────────────────────────

function verifyPage(heading, body, isError = false) {
  const colour = isError ? '#8a0000' : '#1f7a45';
  const icon   = isError
    ? `<svg viewBox="0 0 24 24" width="26" height="26" stroke="#fff" fill="none" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`
    : `<svg viewBox="0 0 24 24" width="26" height="26" stroke="#fff" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mute Points — ${heading}</title>
  <link href="https://fonts.googleapis.com/css2?family=Josefin+Sans:wght@300;400;700&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Josefin Sans',sans-serif;background:#4C0000;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
    .card{background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 12px 48px rgba(0,0,0,.35);max-width:480px;width:100%;text-align:center}
    .card-top{background:#4C0000;padding:40px 36px 36px}
    .mark{width:52px;height:52px;background:${colour};border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px}
    .card-top h1{font-size:22px;font-weight:700;letter-spacing:.04em;color:#fff;margin-bottom:8px}
    .brand{font-size:11px;font-weight:700;letter-spacing:.3em;text-transform:uppercase;color:rgba(255,255,255,.55);margin-bottom:18px}
    .card-body{padding:32px 36px 40px}
    .card-body p{font-size:15px;font-weight:300;color:#555;line-height:1.75;margin-bottom:24px}
    a.btn{display:inline-block;background:#4C0000;color:#fff;font-family:'Josefin Sans',sans-serif;font-size:12px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;padding:13px 36px;border-radius:4px;text-decoration:none}
    a.btn:hover{background:#6B0000}
  </style>
</head>
<body>
  <div class="card">
    <div class="card-top">
      <p class="brand">Mute Points</p>
      <div class="mark">${icon}</div>
      <h1>${heading}</h1>
    </div>
    <div class="card-body">
      <p>${body}</p>
      <a href="${SITE_URL}" class="btn">View the noticeboard</a>
    </div>
  </div>
</body>
</html>`;
}

// ── Public API ────────────────────────────────────────────────────────────────

app.get('/api/challenges', async (req, res) => {
  cleanup().catch(console.error);
  try {
    const { rows } = await pool.query(`
      SELECT
        c.id, c.title, c.position_a, c.position_b, c.challenger_position,
        c.challenger_name, c.challenger_links, c.status, c.created_at,
        a.acceptor_name, a.acceptor_links, a.created_at AS accepted_at,
        CASE WHEN vd1.email IS NOT NULL THEN true ELSE false END AS challenger_verified,
        CASE WHEN vd2.email IS NOT NULL THEN true ELSE false END AS acceptor_verified,
        pa.acceptor_position AS pending_position
      FROM challenges c
      LEFT JOIN acceptances a ON a.challenge_id = c.id
      LEFT JOIN verified_debaters vd1 ON LOWER(vd1.email) = LOWER(c.challenger_email)
      LEFT JOIN verified_debaters vd2 ON LOWER(vd2.email) = LOWER(a.acceptor_email)
      LEFT JOIN pending_acceptances pa ON pa.challenge_id = c.id AND pa.verify_expires > NOW()
      WHERE c.status IN ('open', 'matched', 'closed')
      ORDER BY
        CASE c.status WHEN 'open' THEN 0 WHEN 'matched' THEN 1 ELSE 2 END,
        c.created_at DESC
    `);

    res.json(rows.map(r => ({
      id:                   r.id,
      title:                r.title,
      position_a:           r.position_a,
      position_b:           r.position_b,
      challenger_position:  r.challenger_position,
      challenger_name:      r.challenger_name,
      challenger_links:     normalizeLinks(r.challenger_links),
      challenger_verified:  r.challenger_verified,
      status:               r.status,
      created_at:           r.created_at,
      acceptor_name:        r.acceptor_name  ?? null,
      acceptor_links:       normalizeLinks(r.acceptor_links),
      acceptor_verified:    r.acceptor_verified,
      accepted_at:          r.accepted_at    ?? null,
      pending_position:     r.pending_position ?? null,
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Create a challenge — saves as pending, sends verification email
app.post('/api/challenges', submitLimit, async (req, res) => {
  const b = req.body;
  if (b._hp) return res.status(400).json({ error: 'Invalid submission.' });

  const title  = trimStr(b.title, 200);
  const posA   = trimStr(b.position_a, 100);
  const posB   = trimStr(b.position_b, 100);
  const defPos = b.challenger_position === 'A' || b.challenger_position === 'B' ? b.challenger_position : null;
  const name   = trimStr(b.name, 100);
  const email  = parseEmail(b.email);
  const links  = parseLinks(b.links);

  if (!title)  return res.status(400).json({ error: 'Debate title is required.' });
  if (!posA)   return res.status(400).json({ error: 'Position A is required.' });
  if (!posB)   return res.status(400).json({ error: 'Position B is required.' });
  if (!defPos) return res.status(400).json({ error: 'Please select which position you will defend.' });
  if (!name)   return res.status(400).json({ error: 'Your name is required.' });
  if (!email)  return res.status(400).json({ error: 'A valid email address is required.' });

  const id    = randomUUID();
  const token = randomUUID();

  try {
    await pool.query(`
      INSERT INTO challenges
        (id, title, position_a, position_b, challenger_position,
         challenger_name, challenger_email, challenger_links,
         status, verify_token, verify_expires)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9, NOW() + INTERVAL '24 hours')
    `, [id, title, posA, posB, defPos, name, email, JSON.stringify(links), token]);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error.' });
  }

  const defLabel = defPos === 'A' ? posA : posB;
  sendMail(
    email,
    `Verify your Mute Points debate challenge`,
    `Hi ${name},\n\n` +
    `You've posted a debate challenge on Mute Points:\n\n` +
    `"${title}"\n` +
    `Your position: ${defLabel}\n\n` +
    `Please click the link below to verify your email and publish your challenge:\n\n` +
    `${SITE_URL}/verify/challenge/${token}\n\n` +
    `This link expires in 24 hours. If you didn't post this challenge, you can ignore this email.\n\n` +
    `Mute Points`
  );

  res.json({ success: true, pendingVerification: true });
});

// Accept a challenge — saves as pending_acceptance, sends verification email
app.post('/api/challenges/:id/accept', submitLimit, async (req, res) => {
  const { id } = req.params;
  const b = req.body;
  if (b._hp) return res.status(400).json({ error: 'Invalid submission.' });

  cleanup().catch(console.error);

  try {
    const { rows } = await pool.query(
      `SELECT * FROM challenges WHERE id = $1 AND status = 'open'`, [id]
    );
    const challenge = rows[0];
    if (!challenge) return res.status(409).json({ error: 'This challenge is no longer available.' });

    const existing = await pool.query(
      `SELECT id FROM pending_acceptances WHERE challenge_id = $1 AND verify_expires > NOW()`, [id]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "Someone else has just claimed this position — if they don't confirm within 24 hours it will become available again.",
      });
    }

    const name     = trimStr(b.name, 100);
    const email    = parseEmail(b.email);
    const links    = parseLinks(b.links);
    const position = trimStr(b.position, 100) || null;

    if (!name)  return res.status(400).json({ error: 'Your name is required.' });
    if (!email) return res.status(400).json({ error: 'A valid email address is required.' });

    const pendingId = randomUUID();
    const token     = randomUUID();

    try {
      await pool.query(`
        INSERT INTO pending_acceptances
          (id, challenge_id, acceptor_name, acceptor_email, acceptor_links,
           acceptor_position, verify_token, verify_expires)
        VALUES ($1,$2,$3,$4,$5,$6,$7, NOW() + INTERVAL '24 hours')
      `, [pendingId, id, name, email, JSON.stringify(links), position, token]);
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({
          error: "Someone else has just claimed this position — if they don't confirm within 24 hours it will become available again.",
        });
      }
      throw err;
    }

    const acceptorPos = position || (challenge.challenger_position === 'A' ? challenge.position_b : challenge.position_a);
    sendMail(
      email,
      `Confirm your place in a Mute Points debate`,
      `Hi ${name},\n\n` +
      `You've signed up for a debate on Mute Points:\n\n` +
      `"${challenge.title}"\n` +
      `Your position: ${acceptorPos}\n\n` +
      `Please click the link below to confirm your place:\n\n` +
      `${SITE_URL}/verify/accept/${token}\n\n` +
      `This link expires in 24 hours. If you didn't sign up for this, you can ignore this email.\n\n` +
      `Mute Points`
    );

    res.json({ success: true, pendingVerification: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── Verification endpoints ────────────────────────────────────────────────────

app.get('/verify/challenge/:token', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT * FROM challenges
      WHERE verify_token = $1 AND status = 'pending' AND verify_expires > NOW()
    `, [req.params.token]);
    const challenge = rows[0];

    if (!challenge) {
      return res.send(verifyPage(
        'Link expired or invalid',
        'This verification link has expired or has already been used. Please post your challenge again.',
        true
      ));
    }

    await pool.query(
      `UPDATE challenges SET status = 'open', verify_token = NULL, verify_expires = NULL WHERE id = $1`,
      [challenge.id]
    );

    const defLabel = challenge.challenger_position === 'A' ? challenge.position_a : challenge.position_b;
    const oppLabel = challenge.challenger_position === 'A' ? challenge.position_b : challenge.position_a;

    if (ORGANISER_EMAIL) {
      sendMail(
        ORGANISER_EMAIL,
        `New verified debate challenge: "${challenge.title}"`,
        `A new debate challenge has been verified and published.\n\n` +
        `Debate:     ${challenge.title}\n` +
        `Challenger: ${challenge.challenger_name} (${challenge.challenger_email})\n` +
        `Defending:  ${defLabel}\n` +
        `Seeking:    ${oppLabel}\n\n` +
        `View: ${SITE_URL}\n` +
        `Admin: ${SITE_URL}/admin`
      );
    }

    res.send(verifyPage(
      'Challenge published!',
      `Your debate challenge "<strong>${challenge.title}</strong>" is now live on the noticeboard.`
    ));
  } catch (err) {
    console.error(err);
    res.status(500).send(verifyPage('Something went wrong', 'Please try again later.', true));
  }
});

app.get('/verify/accept/:token', async (req, res) => {
  try {
    const { rows: pRows } = await pool.query(`
      SELECT * FROM pending_acceptances
      WHERE verify_token = $1 AND verify_expires > NOW()
    `, [req.params.token]);
    const pending = pRows[0];

    if (!pending) {
      return res.send(verifyPage(
        'Link expired or invalid',
        'This verification link has expired or has already been used. Please return to the noticeboard and try accepting the challenge again.',
        true
      ));
    }

    const { rows: cRows } = await pool.query(
      `SELECT * FROM challenges WHERE id = $1 AND status = 'open'`, [pending.challenge_id]
    );
    const challenge = cRows[0];

    if (!challenge) {
      await pool.query(`DELETE FROM pending_acceptances WHERE id = $1`, [pending.id]);
      return res.send(verifyPage(
        'Challenge no longer available',
        'This challenge has already been matched or removed. Please check the noticeboard for other open challenges.',
        true
      ));
    }

    const bothOpen = !challenge.challenger_position;
    const acceptorPos = pending.acceptor_position || (challenge.challenger_position === 'A' ? challenge.position_b : challenge.position_a);

    // Atomic update
    const client = await pool.connect();
    let raceCondition = false;
    try {
      await client.query('BEGIN');

      if (bothOpen) {
        // First person to confirm claims their side — convert to a normal open challenge
        const claimedA = pending.acceptor_position === challenge.position_a;
        const newPos = claimedA ? 'A' : 'B';
        const result = await client.query(
          `UPDATE challenges
           SET challenger_name = $1, challenger_email = $2, challenger_links = $3, challenger_position = $4
           WHERE id = $5 AND status = 'open' AND (challenger_position IS NULL OR challenger_position = '')`,
          [pending.acceptor_name, pending.acceptor_email, JSON.stringify(pending.acceptor_links), newPos, challenge.id]
        );
        if (result.rowCount === 0) {
          raceCondition = true;
          await client.query('ROLLBACK');
        } else {
          await client.query(`DELETE FROM pending_acceptances WHERE id = $1`, [pending.id]);
          await client.query('COMMIT');
        }
      } else {
        const result = await client.query(
          `UPDATE challenges SET status = 'matched' WHERE id = $1 AND status = 'open'`,
          [challenge.id]
        );
        if (result.rowCount === 0) {
          raceCondition = true;
          await client.query('ROLLBACK');
        } else {
          await client.query(`
            INSERT INTO acceptances (id, challenge_id, acceptor_name, acceptor_email, acceptor_links)
            VALUES ($1,$2,$3,$4,$5)
          `, [randomUUID(), challenge.id, pending.acceptor_name, pending.acceptor_email, JSON.stringify(pending.acceptor_links)]);
          await client.query(`DELETE FROM pending_acceptances WHERE id = $1`, [pending.id]);
          await client.query('COMMIT');
        }
      }
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    if (raceCondition) {
      return res.send(verifyPage(
        'Position already taken',
        'Someone else confirmed just before you. Please check the noticeboard for other open sides.',
        true
      ));
    }

    if (bothOpen) {
      if (ORGANISER_EMAIL) {
        sendMail(
          ORGANISER_EMAIL,
          `Side claimed: "${challenge.title}"`,
          `Someone has claimed a side on Mute Points!\n\n` +
          `Debate: ${challenge.title}\n` +
          `${pending.acceptor_name} will argue: ${acceptorPos}\n\n` +
          `Contact: ${pending.acceptor_name} (${pending.acceptor_email})\n\n` +
          `Admin: ${SITE_URL}/admin`
        );
      }
      res.send(verifyPage(
        'You\'re on!',
        `You've claimed the <strong>${acceptorPos}</strong> side of "<strong>${challenge.title}</strong>". ` +
        `We'll be in touch once an opponent signs up for the other side.`
      ));
    } else {
      const challengerPos = challenge.challenger_position === 'A' ? challenge.position_a : challenge.position_b;
      if (ORGANISER_EMAIL) {
        sendMail(
          ORGANISER_EMAIL,
          `Debate matched: "${challenge.title}"`,
          `A debate has been matched on Mute Points!\n\n` +
          `Debate:    ${challenge.title}\n\n` +
          `${challenge.challenger_name} will argue: ${challengerPos}\n` +
          `${pending.acceptor_name} will argue: ${acceptorPos}\n\n` +
          `Challenger: ${challenge.challenger_name} (${challenge.challenger_email})\n` +
          `Acceptor:   ${pending.acceptor_name} (${pending.acceptor_email})\n\n` +
          `Admin: ${SITE_URL}/admin`
        );
      }
      res.send(verifyPage(
        'Acceptance confirmed!',
        `You're confirmed to debate "<strong>${challenge.title}</strong>", arguing ${acceptorPos}. ` +
        `Mute Points will be in touch to arrange the debate.`
      ));
    }
  } catch (err) {
    console.error(err);
    res.status(500).send(verifyPage('Something went wrong', 'Please try again later.', true));
  }
});

// ── Report a challenge ────────────────────────────────────────────────────────

app.post('/api/report', reportLimit, async (req, res) => {
  const b = req.body;
  if (b._hp) return res.status(400).json({ error: 'Invalid submission.' });

  const challengeId = trimStr(b.challenge_id, 36);
  const reason      = trimStr(b.reason, 500);

  try {
    const { rows } = await pool.query(`SELECT title FROM challenges WHERE id = $1`, [challengeId]);
    if (!rows[0]) return res.status(404).json({ error: 'Challenge not found.' });

    if (ORGANISER_EMAIL) {
      sendMail(
        ORGANISER_EMAIL,
        `Report: "${rows[0].title}"`,
        `A challenge has been reported on Mute Points.\n\n` +
        `Challenge: ${rows[0].title}\n` +
        `Reason: ${reason || '(none given)'}\n\n` +
        `Admin: ${SITE_URL}/admin`
      );
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── Admin API ─────────────────────────────────────────────────────────────────

app.get('/admin/api/challenges', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        c.*, a.acceptor_name, a.acceptor_email, a.acceptor_links,
        a.created_at AS accepted_at,
        pa.acceptor_name AS pending_name, pa.acceptor_email AS pending_email,
        pa.verify_expires AS pending_expires
      FROM challenges c
      LEFT JOIN acceptances a ON a.challenge_id = c.id
      LEFT JOIN pending_acceptances pa ON pa.challenge_id = c.id
      ORDER BY c.created_at DESC
    `);
    res.json(rows.map(r => ({
      ...r,
      challenger_links: normalizeLinks(r.challenger_links),
      acceptor_links:   normalizeLinks(r.acceptor_links),
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/admin/api/challenges/:id/status', requireAdmin, async (req, res) => {
  const { status } = req.body;
  if (!['open', 'closed', 'deleted'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status.' });
  }
  try {
    await pool.query('UPDATE challenges SET status = $1 WHERE id = $2', [status, req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.get('/admin/api/verified-debaters', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM verified_debaters ORDER BY added_at DESC`);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/admin/api/verified-debaters', requireAdmin, async (req, res) => {
  const email = parseEmail(req.body.email);
  const name  = trimStr(req.body.name || req.body.display_name || '', 100);
  if (!email) return res.status(400).json({ error: 'Valid email required.' });
  if (!name)  return res.status(400).json({ error: 'Display name required.' });
  try {
    await pool.query(
      `INSERT INTO verified_debaters (email, display_name)
       VALUES ($1, $2)
       ON CONFLICT (email) DO UPDATE SET display_name = EXCLUDED.display_name`,
      [email, name]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.delete('/admin/api/verified-debaters/:email', requireAdmin, async (req, res) => {
  try {
    await pool.query(`DELETE FROM verified_debaters WHERE email = $1`, [req.params.email]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── Admin page ────────────────────────────────────────────────────────────────

app.get('/admin/logout', (req, res) => {
  const cookieHeader = req.headers.cookie || '';
  const m = cookieHeader.match(/(?:^|;\s*)admin_session=([^;]+)/);
  if (m) adminSessions.delete(m[1]);
  res.clearCookie('admin_session', { path: '/admin' });
  res.set('WWW-Authenticate', 'Basic realm="Mute Points Admin"').status(401).end('Logged out');
});

app.get('/admin', requireAdmin, (req, res) => {
  // Set a session cookie so fetch() calls from the admin page don't need to
  // re-send Basic Auth credentials (browsers often skip that for POST).
  const token = createAdminSession();
  const secure = SITE_URL.startsWith('https://');
  res.cookie('admin_session', token, {
    httpOnly: true,
    sameSite: 'Strict',
    secure,
    path: '/admin',
    maxAge: 24 * 60 * 60 * 1000,
  });
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ── Start ─────────────────────────────────────────────────────────────────────

initSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Mute Points Debates running at http://localhost:${PORT}`);
      if (!mailer) console.log('  (Email disabled — set SMTP_* vars in .env to enable)');
    });
  })
  .catch(err => {
    console.error('Failed to initialise database:', err);
    process.exit(1);
  });
