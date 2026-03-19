const express = require('express');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// ========== SECURITY ==========
app.use(helmet({
  contentSecurityPolicy: false, // Allow inline scripts in our HTML pages
}));
app.use(express.json({ limit: '10kb' })); // Limit body size

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  message: { error: 'יותר מדי בקשות, נסו שוב בעוד דקה' },
});
const registerLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10, // 10 registrations per minute per IP
  message: { error: 'יותר מדי הרשמות, נסו שוב בעוד דקה' },
});
app.use('/api/', apiLimiter);

// Admin token — generated on startup, shown in console
const ADMIN_TOKEN = crypto.randomBytes(16).toString('hex');

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'נדרשת הרשאת מנהל' });
  }
  next();
}

app.use(express.static(path.join(__dirname, 'public')));

// ========== DYNAMIC CONFIG ==========
let eventConfig = {
  configured: false,
  maxCapacity: 50,
  slotDurationMin: 30,
  numSlots: 5,
  startTime: null,
  slots: [],
};

const MAX_NAME_LEN = 100;
const MAX_PHONE_LEN = 20;
const MAX_SSE_CLIENTS = 200;

function generateSlots(startTime, numSlots, slotDurationMin) {
  const slots = [];
  for (let i = 0; i < numSlots; i++) {
    const slotStart = new Date(startTime.getTime() + i * slotDurationMin * 60000);
    const slotEnd = new Date(slotStart.getTime() + slotDurationMin * 60000);
    slots.push({
      index: i,
      label: `${formatHM(slotStart)} - ${formatHM(slotEnd)}`,
      startTime: slotStart.getTime(),
      endTime: slotEnd.getTime(),
    });
  }
  return slots;
}

function formatHM(d) {
  return d.toLocaleTimeString('he-IL', { hour: '2-digit', minute: '2-digit' });
}

function sanitizeName(name) {
  return (name || '').trim().slice(0, MAX_NAME_LEN);
}

function sanitizePhone(phone) {
  return (phone || '').trim().slice(0, MAX_PHONE_LEN);
}

// CSV injection protection: prefix cells starting with dangerous chars
function csvSafe(str) {
  if (typeof str !== 'string') return str;
  if (/^[=+\-@\t\r]/.test(str)) return `'${str}`;
  return str;
}

// In-memory state
const guests = new Map();
const preRegistrations = new Map();
const sseClients = {
  admin: new Set(),  // Full state (authenticated)
  public: new Set(), // Counts only (no PII)
};

// ========== SSE ==========

// Public SSE — counts only, no names/phones/codes
app.get('/api/events/public', (req, res) => {
  if (sseClients.public.size >= MAX_SSE_CLIENTS) {
    return res.status(503).json({ error: 'Too many connections' });
  }
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });
  res.write('\n');
  sseClients.public.add(res);
  res.write(`data: ${JSON.stringify(getPublicState())}\n\n`);
  req.on('close', () => sseClients.public.delete(res));
});

// Admin SSE — full state (requires token)
app.get('/api/events', (req, res) => {
  const token = req.query.token;
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'נדרשת הרשאת מנהל' });
  }
  if (sseClients.admin.size >= 20) {
    return res.status(503).json({ error: 'Too many admin connections' });
  }
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });
  res.write('\n');
  sseClients.admin.add(res);
  res.write(`data: ${JSON.stringify(getAdminState())}\n\n`);
  req.on('close', () => sseClients.admin.delete(res));
});

function broadcast() {
  const adminData = JSON.stringify(getAdminState());
  for (const client of sseClients.admin) {
    client.write(`data: ${adminData}\n\n`);
  }
  const publicData = JSON.stringify(getPublicState());
  for (const client of sseClients.public) {
    client.write(`data: ${publicData}\n\n`);
  }
}

function getActiveCount() {
  return [...guests.values()].filter(g => !g.checkoutTime).length;
}

// Public state — no PII, no codes, just counts
function getPublicState() {
  const now = Date.now();
  const activeCount = getActiveCount();
  const regList = [...preRegistrations.values()];

  const slotStats = eventConfig.slots.map(slot => {
    const slotRegs = regList.filter(r => r.slotIndex === slot.index);
    return {
      ...slot,
      registered: slotRegs.length,
      arrived: slotRegs.filter(r => r.arrived).length,
      pending: slotRegs.length - slotRegs.filter(r => r.arrived).length,
    };
  });

  let currentSlotIndex = -1;
  for (const slot of eventConfig.slots) {
    if (now >= slot.startTime && now < slot.endTime) {
      currentSlotIndex = slot.index;
      break;
    }
  }

  return {
    configured: eventConfig.configured,
    currentCount: activeCount,
    maxCapacity: eventConfig.maxCapacity,
    totalVisitors: guests.size,
    slots: eventConfig.slots,
    slotStats,
    currentSlotIndex,
  };
}

// Admin state — full details
function getAdminState() {
  const active = [];
  const history = [];
  const now = Date.now();

  for (const g of guests.values()) {
    if (!g.checkoutTime) {
      active.push({ ...g, duration: now - g.checkinTime });
    } else {
      history.push({ ...g, duration: g.checkoutTime - g.checkinTime });
    }
  }

  active.sort((a, b) => a.checkinTime - b.checkinTime);
  history.sort((a, b) => b.checkoutTime - a.checkoutTime);

  const regList = [...preRegistrations.values()];
  const regTotal = regList.length;
  const regArrived = regList.filter(r => r.arrived).length;
  const regPending = regTotal - regArrived;
  const walkinSpotsAvailable = Math.max(0, eventConfig.maxCapacity - active.length - regPending);

  const slotStats = eventConfig.slots.map(slot => {
    const slotRegs = regList.filter(r => r.slotIndex === slot.index);
    return {
      ...slot,
      registered: slotRegs.length,
      arrived: slotRegs.filter(r => r.arrived).length,
      pending: slotRegs.length - slotRegs.filter(r => r.arrived).length,
    };
  });

  let currentSlotIndex = -1;
  for (const slot of eventConfig.slots) {
    if (now >= slot.startTime && now < slot.endTime) {
      currentSlotIndex = slot.index;
      break;
    }
  }

  return {
    configured: eventConfig.configured,
    active,
    history: history.slice(0, 50),
    currentCount: active.length,
    maxCapacity: eventConfig.maxCapacity,
    totalVisitors: guests.size,
    totalCheckedOut: history.length,
    preRegistrations: regList.map(r => ({
      code: r.code,
      name: r.name,
      phone: r.phone,
      registeredAt: r.registeredAt,
      arrived: r.arrived,
      slotIndex: r.slotIndex,
    })),
    regTotal,
    regArrived,
    regPending,
    walkinSpotsAvailable,
    slots: eventConfig.slots,
    slotStats,
    currentSlotIndex,
    slotDurationMin: eventConfig.slotDurationMin,
    numSlots: eventConfig.numSlots,
  };
}

// ========== ADMIN SETUP (authenticated) ==========

app.get('/api/admin/config', requireAdmin, (req, res) => {
  res.json({
    configured: eventConfig.configured,
    maxCapacity: eventConfig.maxCapacity,
    slotDurationMin: eventConfig.slotDurationMin,
    numSlots: eventConfig.numSlots,
    startTime: eventConfig.startTime ? eventConfig.startTime.toISOString() : null,
    slots: eventConfig.slots,
  });
});

app.post('/api/admin/setup', requireAdmin, (req, res) => {
  const { startTime, numSlots, slotDurationMin, maxCapacity } = req.body;

  if (!startTime) return res.status(400).json({ error: 'שעת התחלה נדרשת' });

  const start = new Date(startTime);
  if (isNaN(start.getTime())) return res.status(400).json({ error: 'שעת התחלה לא תקינה' });

  const ns = parseInt(numSlots) || 5;
  const sd = parseInt(slotDurationMin) || 30;
  const mc = parseInt(maxCapacity) || 50;

  if (ns < 1 || ns > 20) return res.status(400).json({ error: 'מספר סבבים חייב להיות בין 1 ל-20' });
  if (sd < 10 || sd > 120) return res.status(400).json({ error: 'משך סבב חייב להיות בין 10 ל-120 דקות' });
  if (mc < 1 || mc > 1000) return res.status(400).json({ error: 'מספר משתתפים חייב להיות בין 1 ל-1000' });

  guests.clear();
  preRegistrations.clear();

  eventConfig.configured = true;
  eventConfig.maxCapacity = mc;
  eventConfig.slotDurationMin = sd;
  eventConfig.numSlots = ns;
  eventConfig.startTime = start;
  eventConfig.slots = generateSlots(start, ns, sd);

  broadcast();
  res.json({ ok: true, slots: eventConfig.slots, maxCapacity: mc, totalCapacity: mc * ns });
});

// ========== PUBLIC SLOTS ==========

app.get('/api/slots', (req, res) => {
  if (!eventConfig.configured) {
    return res.json({ slots: [], configured: false });
  }
  const regList = [...preRegistrations.values()];
  const slots = eventConfig.slots.map(slot => {
    const slotRegCount = regList.filter(r => r.slotIndex === slot.index).length;
    return {
      ...slot,
      registered: slotRegCount,
      available: eventConfig.maxCapacity - slotRegCount,
      full: slotRegCount >= eventConfig.maxCapacity,
    };
  });
  res.json({ slots, configured: true, maxCapacity: eventConfig.maxCapacity });
});

// ========== PRE-REGISTRATION (public, rate-limited) ==========

app.post('/api/register', registerLimiter, (req, res) => {
  if (!eventConfig.configured) return res.status(400).json({ error: 'האירוע טרם הוגדר' });

  const name = sanitizeName(req.body.name);
  const phone = sanitizePhone(req.body.phone);
  if (!name) return res.status(400).json({ error: 'שם נדרש' });

  const si = parseInt(req.body.slotIndex);
  if (isNaN(si) || si < 0 || si >= eventConfig.slots.length) {
    return res.status(400).json({ error: 'יש לבחור חלון זמן' });
  }

  const slotRegCount = [...preRegistrations.values()].filter(r => r.slotIndex === si).length;
  if (slotRegCount >= eventConfig.maxCapacity) {
    return res.status(409).json({ error: 'חלון הזמן הזה מלא, בחרו חלון אחר' });
  }

  const code = crypto.randomBytes(4).toString('hex').toUpperCase();
  const reg = { code, name, phone, registeredAt: Date.now(), arrived: false, slotIndex: si };

  preRegistrations.set(code, reg);
  broadcast();
  res.json({ code, name: reg.name, slotLabel: eventConfig.slots[si].label, slotIndex: si });
});

app.get('/api/register/:code', (req, res) => {
  const reg = preRegistrations.get(req.params.code.toUpperCase());
  if (!reg) return res.status(404).json({ error: 'קוד הרשמה לא נמצא' });
  const slot = eventConfig.slots[reg.slotIndex];
  res.json({ code: reg.code, name: reg.name, arrived: reg.arrived, slotIndex: reg.slotIndex, slotLabel: slot ? slot.label : '' });
});

// Check-in with code
app.post('/api/checkin/code', (req, res) => {
  if (!eventConfig.configured) return res.status(400).json({ error: 'האירוע טרם הוגדר' });
  const { code } = req.body;
  if (!code || typeof code !== 'string') return res.status(400).json({ error: 'קוד נדרש' });

  const reg = preRegistrations.get(code.toUpperCase().slice(0, 20));
  if (!reg) return res.status(404).json({ error: 'קוד הרשמה לא נמצא' });
  if (reg.arrived) return res.status(400).json({ error: 'כבר נרשמת כנוכח/ת' });
  if (getActiveCount() >= eventConfig.maxCapacity) {
    return res.status(409).json({ error: 'האירוע מלא כרגע, נסו שוב בעוד כמה דקות' });
  }

  reg.arrived = true;
  const id = crypto.randomBytes(6).toString('hex');
  const guest = { id, name: reg.name, checkinTime: Date.now(), checkoutTime: null, type: 'preregistered', regCode: reg.code, slotIndex: reg.slotIndex };
  guests.set(id, guest);
  broadcast();
  const slot = eventConfig.slots[reg.slotIndex];
  res.json({ id, name: guest.name, type: 'preregistered', slotLabel: slot ? slot.label : '' });
});

// ========== WALK-IN ==========

app.post('/api/checkin', registerLimiter, (req, res) => {
  if (!eventConfig.configured) return res.status(400).json({ error: 'האירוע טרם הוגדר' });

  const name = sanitizeName(req.body.name);
  if (!name) return res.status(400).json({ error: 'שם נדרש' });

  const activeCount = getActiveCount();
  const now = Date.now();
  const pendingForCurrentAndFuture = [...preRegistrations.values()].filter(r => {
    if (r.arrived) return false;
    const slot = eventConfig.slots[r.slotIndex];
    return slot && now < slot.endTime;
  }).length;

  const walkinAllowed = eventConfig.maxCapacity - activeCount - pendingForCurrentAndFuture;
  if (walkinAllowed <= 0) {
    if (activeCount >= eventConfig.maxCapacity) {
      return res.status(409).json({ error: 'האירוע מלא, יש להמתין ליציאת אורחים' });
    }
    return res.status(409).json({ error: 'המקומות הפנויים שמורים לנרשמים מראש.', reservedFull: true });
  }

  const id = crypto.randomBytes(6).toString('hex');
  const currentSlot = eventConfig.slots.find(s => now >= s.startTime && now < s.endTime);
  const guest = { id, name, checkinTime: Date.now(), checkoutTime: null, type: 'walkin', regCode: null, slotIndex: currentSlot ? currentSlot.index : -1 };
  guests.set(id, guest);
  broadcast();
  res.json({ id, name: guest.name, type: 'walkin' });
});

// ========== CHECK-OUT ==========

app.post('/api/checkout/:id', (req, res) => {
  const guest = guests.get(req.params.id);
  if (!guest) return res.status(404).json({ error: 'אורח לא נמצא' });
  if (guest.checkoutTime) return res.status(400).json({ error: 'האורח כבר יצא' });
  guest.checkoutTime = Date.now();
  broadcast();
  res.json({ ok: true });
});

// ========== ADMIN (authenticated) ==========

app.get('/api/status', requireAdmin, (req, res) => res.json(getAdminState()));

app.post('/api/admin/checkout/:id', requireAdmin, (req, res) => {
  const guest = guests.get(req.params.id);
  if (!guest || guest.checkoutTime) return res.status(404).json({ error: 'אורח לא נמצא' });
  guest.checkoutTime = Date.now();
  broadcast();
  res.json({ ok: true });
});

app.post('/api/admin/release/:code', requireAdmin, (req, res) => {
  const reg = preRegistrations.get(req.params.code);
  if (!reg) return res.status(404).json({ error: 'הרשמה לא נמצאה' });
  if (reg.arrived) return res.status(400).json({ error: 'האורח כבר הגיע, לא ניתן לשחרר' });
  preRegistrations.delete(req.params.code);
  broadcast();
  res.json({ ok: true });
});

app.post('/api/admin/reset', requireAdmin, (req, res) => {
  guests.clear();
  preRegistrations.clear();
  eventConfig.configured = false;
  eventConfig.slots = [];
  eventConfig.startTime = null;
  broadcast();
  res.json({ ok: true });
});

// Admin token endpoint — for setup page to get token
app.get('/api/admin/token', (req, res) => {
  // Only accessible if you know the token (chicken-egg solved via console)
  const token = req.query.token;
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'טוקן לא תקין' });
  }
  res.json({ valid: true });
});

const PORT = process.env.PORT || 3333;
app.listen(PORT, () => {
  console.log(`\n========================================`);
  console.log(`  Event Gate server running on port ${PORT}`);
  console.log(`  Admin Token: ${ADMIN_TOKEN}`);
  console.log(`  Admin URL: http://localhost:${PORT}/admin.html?token=${ADMIN_TOKEN}`);
  console.log(`  Setup URL: http://localhost:${PORT}/setup.html?token=${ADMIN_TOKEN}`);
  console.log(`========================================\n`);
});
