const express = require('express');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const { MongoClient } = require('mongodb');

const app = express();

// ========== SECURITY ==========
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '50kb' }));

const apiLimiter = rateLimit({ windowMs: 60000, max: 120, message: { error: 'יותר מדי בקשות' } });
const registerLimiter = rateLimit({ windowMs: 60000, max: 20, message: { error: 'יותר מדי הרשמות' } });
app.use('/api/', apiLimiter);

// Admin token
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || crypto.randomBytes(16).toString('hex');

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'נדרשת הרשאת מנהל' });
  next();
}

// ========== PERSISTENCE (MongoDB + file fallback) ==========
const MONGO_URI = process.env.MONGODB_URI || process.env.MONGO_URI || '';
const DATA_FILE = path.join(__dirname, 'data.json');

let mongoDb = null;
let mongoConnected = false;

async function connectMongo() {
  if (!MONGO_URI) return false;
  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    mongoDb = client.db('eventgate');
    mongoConnected = true;
    console.log('MongoDB connected successfully');
    return true;
  } catch (e) {
    console.error('MongoDB connection failed:', e.message);
    return false;
  }
}

function loadDBFromFile() {
  try {
    if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {}
  return { events: {}, clients: {}, members: [] };
}

async function loadDB() {
  if (mongoConnected) {
    try {
      const doc = await mongoDb.collection('state').findOne({ _id: 'main' });
      if (doc) { delete doc._id; return doc; }
    } catch (e) { console.error('MongoDB load failed:', e.message); }
  }
  return loadDBFromFile();
}

async function saveDB() {
  // Save to file (backup)
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); } catch (e) {}
  // Save to MongoDB
  if (mongoConnected) {
    try {
      await mongoDb.collection('state').replaceOne(
        { _id: 'main' },
        { _id: 'main', ...db },
        { upsert: true }
      );
    } catch (e) { console.error('MongoDB save failed:', e.message); }
  }
}

let db = loadDBFromFile();

// Auto-save every 30 seconds
setInterval(saveDB, 30000);

// ========== HELPERS ==========
function randomCode(len = 6) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let c = '';
  for (let i = 0; i < len; i++) c += chars[Math.floor(Math.random() * chars.length)];
  return c;
}

function randomId() { return crypto.randomBytes(6).toString('hex'); }

function sanitize(str, max = 100) { return (str || '').trim().slice(0, max); }

function formatHM(ts) {
  return new Date(ts).toLocaleTimeString('he-IL', { hour: '2-digit', minute: '2-digit' });
}

function generateSlots(startTime, numSlots, durMin) {
  const slots = [];
  for (let i = 0; i < numSlots; i++) {
    const ss = startTime + i * durMin * 60000;
    const se = ss + durMin * 60000;
    slots.push({ index: i, label: `${formatHM(ss)} - ${formatHM(se)}`, startTime: ss, endTime: se });
  }
  return slots;
}

function activeCount(event) {
  return Object.values(event.guests || {}).filter(g => !g.checkoutTime).reduce((sum, g) => sum + (g.groupSize || 1), 0);
}

function formatPhoneForWA(phone) {
  if (!phone) return '';
  let p = phone.replace(/[^0-9]/g, '');
  if (p.startsWith('0')) p = '972' + p.slice(1);
  return p;
}

// ========== STATIC FILES ==========
app.use(express.static(path.join(__dirname, 'public')));

// ========== API: EVENTS ==========

// List all events (admin)
app.get('/api/events', requireAdmin, (req, res) => {
  const list = Object.values(db.events).map(ev => ({
    id: ev.id, clientName: ev.clientName, eventName: ev.eventName,
    contactName: ev.contactName, contactPhone: ev.contactPhone,
    date: ev.date, clientToken: ev.clientToken,
    configured: ev.configured, startTime: ev.startTime,
    numSlots: ev.numSlots, maxCapacity: ev.maxCapacity,
    attractions: ev.attractions, eventAddress: ev.eventAddress,
    guestCount: Object.values(ev.guests || {}).reduce((sum, g) => sum + (g.groupSize || 1), 0),
    preRegCount: Object.values(ev.preRegs || {}).reduce((sum, r) => sum + (r.participants || 1), 0),
    activeCount: activeCount(ev),
    createdAt: ev.createdAt,
  }));
  res.json({ events: list, adminToken: ADMIN_TOKEN });
});

// Get single event (public — for registration page)
app.get('/api/events/:id', (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev) return res.status(404).json({ error: 'אירוע לא נמצא' });
  // Public view — no admin data
  const preRegs = Object.values(ev.preRegs || {});
  const slotCounts = {};
  (ev.slots || []).forEach(s => { slotCounts[s.index] = 0; });
  preRegs.forEach(r => {
    const p = r.participants || 1;
    slotCounts[r.slotIndex] = (slotCounts[r.slotIndex] || 0) + p;
  });
  res.json({
    id: ev.id, clientName: ev.clientName, eventName: ev.eventName,
    configured: ev.configured, startTime: ev.startTime,
    slots: ev.slots, numSlots: ev.numSlots, maxCapacity: ev.maxCapacity,
    slotDurationMin: ev.slotDurationMin,
    attractions: ev.attractions, eventAddress: ev.eventAddress,
    date: ev.date, slotCounts,
  });
});

// Get event by client token (for client view)
app.get('/api/client/:token', (req, res) => {
  const ev = Object.values(db.events).find(e => e.clientToken === req.params.token);
  if (!ev) return res.status(404).json({ error: 'אירוע לא נמצא' });
  const ac = activeCount(ev);
  const preRegs = Object.values(ev.preRegs || {});
  res.json({
    id: ev.id, clientName: ev.clientName, eventName: ev.eventName,
    configured: ev.configured, startTime: ev.startTime,
    slots: ev.slots, numSlots: ev.numSlots, maxCapacity: ev.maxCapacity,
    attractions: ev.attractions, eventAddress: ev.eventAddress,
    date: ev.date, activeCount: ac,
    totalGuests: Object.values(ev.guests || {}).reduce((sum, g) => sum + (g.groupSize || 1), 0),
    totalRegs: preRegs.reduce((sum, r) => sum + (r.participants || 1), 0),
    pendingRegs: preRegs.filter(r => !r.arrived).reduce((sum, r) => sum + (r.participants || 1), 0),
  });
});

// Create event (admin)
app.post('/api/events', requireAdmin, (req, res) => {
  const { clientName, eventName, contactName, contactPhone, date, time,
    numSlots, slotDurationMin, maxCapacity, attractions, eventAddress } = req.body;

  if (!date || !time) return res.status(400).json({ error: 'תאריך ושעה נדרשים' });

  const id = randomId();
  const startTime = new Date(`${date}T${time}`).getTime();
  if (isNaN(startTime)) return res.status(400).json({ error: 'תאריך/שעה לא תקינים' });

  const ns = Math.max(1, Math.min(20, parseInt(numSlots) || 5));
  const dur = parseInt(slotDurationMin) || 30;
  const mc = Math.max(1, Math.min(1000, parseInt(maxCapacity) || 50));

  const ev = {
    id, configured: true,
    clientName: sanitize(clientName), eventName: sanitize(eventName),
    contactName: sanitize(contactName), contactPhone: sanitize(contactPhone, 20),
    date, startTime, numSlots: ns, slotDurationMin: dur, maxCapacity: mc,
    slots: generateSlots(startTime, ns, dur),
    clientToken: randomCode(8),
    attractions: sanitize(attractions, 500), eventAddress: sanitize(eventAddress, 200),
    guests: {}, preRegs: {}, createdAt: Date.now(),
  };

  db.events[id] = ev;
  saveDB();
  res.json({ event: ev });
});

// Update event (admin)
app.put('/api/events/:id', requireAdmin, (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev) return res.status(404).json({ error: 'אירוע לא נמצא' });

  const fields = ['clientName', 'eventName', 'contactName', 'contactPhone', 'attractions', 'eventAddress'];
  fields.forEach(f => { if (req.body[f] !== undefined) ev[f] = sanitize(req.body[f], f === 'attractions' ? 500 : 200); });

  if (req.body.date && req.body.time) {
    const startTime = new Date(`${req.body.date}T${req.body.time}`).getTime();
    if (!isNaN(startTime)) {
      ev.date = req.body.date;
      ev.startTime = startTime;
      ev.numSlots = Math.max(1, Math.min(20, parseInt(req.body.numSlots) || ev.numSlots));
      ev.slotDurationMin = parseInt(req.body.slotDurationMin) || ev.slotDurationMin;
      ev.maxCapacity = Math.max(1, Math.min(1000, parseInt(req.body.maxCapacity) || ev.maxCapacity));
      ev.slots = generateSlots(startTime, ev.numSlots, ev.slotDurationMin);
    }
  }
  saveDB();
  res.json({ event: ev });
});

// Delete event (admin)
app.delete('/api/events/:id', requireAdmin, (req, res) => {
  if (!db.events[req.params.id]) return res.status(404).json({ error: 'אירוע לא נמצא' });
  delete db.events[req.params.id];
  saveDB();
  res.json({ ok: true });
});

// ========== API: REGISTRATION ==========

// Pre-register for event (public)
app.post('/api/events/:id/register', registerLimiter, (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev || !ev.configured) return res.status(404).json({ error: 'אירוע לא נמצא' });

  const { name, phone, slotIndex, participants } = req.body;
  if (!name || name.trim().length === 0) return res.status(400).json({ error: 'נא להזין שם' });
  if (!phone || phone.trim().length < 9) return res.status(400).json({ error: 'נא להזין מספר טלפון' });

  // Check duplicate phone registration
  const normalNewPhone = phone.replace(/[^0-9]/g, '');
  const existingReg = Object.values(ev.preRegs).find(r => r.phone && r.phone.replace(/[^0-9]/g, '') === normalNewPhone);
  if (existingReg) {
    return res.status(400).json({ error: 'מספר הטלפון כבר רשום לאירוע זה', existingCode: existingReg.code, existingSlot: existingReg.slotIndex, existingParticipants: existingReg.participants });
  }
  if (slotIndex === undefined || slotIndex < 0 || slotIndex >= ev.slots.length) {
    return res.status(400).json({ error: 'חלון זמן לא תקין' });
  }

  const pCount = Math.max(1, Math.min(4, parseInt(participants) || 1));
  const slotParticipants = Object.values(ev.preRegs).filter(r => r.slotIndex === slotIndex)
    .reduce((sum, r) => sum + (r.participants || 1), 0);
  if (slotParticipants + pCount > ev.maxCapacity) {
    return res.status(400).json({ error: `אין מספיק מקומות (${ev.maxCapacity - slotParticipants} פנויים)` });
  }

  const code = randomCode(6);
  ev.preRegs[code] = {
    code, name: sanitize(name), phone: sanitize(phone, 20),
    registeredAt: Date.now(), arrived: false,
    slotIndex: parseInt(slotIndex), participants: pCount,
  };
  saveDB();
  res.json({ code, slot: ev.slots[slotIndex] });
});

// ========== API: CHECK-IN ==========

// Check-in with code or phone (admin/staff)
app.post('/api/events/:id/checkin', requireAdmin, (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev || !ev.configured) return res.status(404).json({ error: 'אירוע לא נמצא' });

  const { code, name, groupSize, type, phone } = req.body;

  if (type === 'walkin') {
    // Walk-in checkin
    if (!name) return res.status(400).json({ error: 'נא להזין שם' });
    if (!phone || phone.trim().length < 9) return res.status(400).json({ error: 'נא להזין מספר טלפון' });

    // Check if phone already exists in pre-regs or guests
    const normalPhone = phone.replace(/[^0-9]/g, '');
    const existingReg = Object.values(ev.preRegs).find(r => r.phone && r.phone.replace(/[^0-9]/g, '') === normalPhone);
    if (existingReg) {
      return res.status(400).json({ error: `מספר הטלפון כבר רשום מראש (קוד: ${existingReg.code})` });
    }
    const existingGuest = Object.values(ev.guests).filter(g => !g.checkoutTime).find(g => g.phone && g.phone.replace(/[^0-9]/g, '') === normalPhone);
    if (existingGuest) {
      return res.status(400).json({ error: 'מספר הטלפון כבר נמצא באירוע' });
    }

    const gs = Math.max(1, Math.min(20, parseInt(groupSize) || 1));
    const ac = activeCount(ev);
    if (ac + gs > ev.maxCapacity) return res.status(400).json({ error: 'האירוע מלא' });

    const id = randomId();
    ev.guests[id] = {
      id, name: sanitize(name), phone: sanitize(phone, 20),
      checkinTime: Date.now(), checkoutTime: null,
      type: 'walkin', regCode: null, slotIndex: -1, groupSize: gs,
    };
    saveDB();
    return res.json({ guest: ev.guests[id] });
  }

  // Pre-registered checkin
  if (!code) return res.status(400).json({ error: 'נא להזין קוד' });
  const input = code.toUpperCase().trim();
  let reg = ev.preRegs[input];
  let matchedCode = input;

  // Try phone number
  if (!reg) {
    const normalPhone = input.replace(/[^0-9]/g, '');
    if (normalPhone.length >= 9) {
      const match = Object.entries(ev.preRegs).find(([, r]) => r.phone && r.phone.replace(/[^0-9]/g, '') === normalPhone);
      if (match) { matchedCode = match[0]; reg = match[1]; }
    }
  }
  if (!reg) return res.status(404).json({ error: 'לא נמצאה הרשמה' });
  if (reg.arrived) return res.status(400).json({ error: 'כבר נרשם/ה כנוכח/ת' });

  const actualGroup = Math.max(1, Math.min(reg.participants || 1, parseInt(groupSize) || reg.participants || 1));
  const ac = activeCount(ev);
  if (ac + actualGroup > ev.maxCapacity) return res.status(400).json({ error: 'האירוע מלא' });

  reg.arrived = true;
  reg.actualParticipants = actualGroup;
  const id = randomId();
  ev.guests[id] = {
    id, name: reg.name, checkinTime: Date.now(), checkoutTime: null,
    type: 'preregistered', regCode: matchedCode, slotIndex: reg.slotIndex, groupSize: actualGroup,
  };
  saveDB();
  res.json({ guest: ev.guests[id], reg });
});

// Check-out (admin)
app.post('/api/events/:id/checkout/:guestId', requireAdmin, (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev) return res.status(404).json({ error: 'אירוע לא נמצא' });
  const guest = ev.guests[req.params.guestId];
  if (!guest) return res.status(404).json({ error: 'אורח לא נמצא' });
  guest.checkoutTime = Date.now();
  saveDB();
  res.json({ guest });
});

// Release pre-registration (admin)
app.post('/api/events/:id/release/:code', requireAdmin, (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev) return res.status(404).json({ error: 'אירוע לא נמצא' });
  if (!ev.preRegs[req.params.code]) return res.status(404).json({ error: 'רישום לא נמצא' });
  delete ev.preRegs[req.params.code];
  saveDB();
  res.json({ ok: true });
});

// Get full event state (admin)
app.get('/api/events/:id/full', requireAdmin, (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev) return res.status(404).json({ error: 'אירוע לא נמצא' });
  res.json(ev);
});

// ========== API: MEMBERS ==========
app.post('/api/members', (req, res) => {
  const { name, phone, city, childAges } = req.body;
  if (!name || !phone) return res.status(400).json({ error: 'שם וטלפון נדרשים' });
  if (!db.members) db.members = [];
  const exists = db.members.find(m => m.phone === phone);
  if (exists) { exists.name = sanitize(name); exists.city = sanitize(city); exists.childAges = sanitize(childAges); }
  else db.members.push({ name: sanitize(name), phone: sanitize(phone, 20), city: sanitize(city, 50), childAges: sanitize(childAges, 50), joinedAt: Date.now() });
  saveDB();
  res.json({ ok: true });
});

app.get('/api/members', requireAdmin, (req, res) => {
  res.json({ members: db.members || [] });
});

// Update registration (by phone — allows guest to change participant count)
app.put('/api/events/:id/register', (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev || !ev.configured) return res.status(404).json({ error: 'אירוע לא נמצא' });
  const { phone, participants, slotIndex } = req.body;
  if (!phone) return res.status(400).json({ error: 'נא להזין מספר טלפון' });
  const normalPhone = phone.replace(/[^0-9]/g, '');
  const entry = Object.entries(ev.preRegs).find(([, r]) => r.phone && r.phone.replace(/[^0-9]/g, '') === normalPhone);
  if (!entry) return res.status(404).json({ error: 'לא נמצאה הרשמה עם מספר זה' });
  const [code, reg] = entry;
  if (reg.arrived) return res.status(400).json({ error: 'לא ניתן לעדכן — כבר נכנסת לאירוע' });
  if (participants !== undefined) reg.participants = Math.max(1, Math.min(4, parseInt(participants) || 1));
  if (slotIndex !== undefined && slotIndex >= 0 && slotIndex < ev.slots.length) reg.slotIndex = parseInt(slotIndex);
  saveDB();
  res.json({ code, reg });
});

// ========== API: RATINGS ==========
app.post('/api/events/:id/rate', (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev) return res.status(404).json({ error: 'אירוע לא נמצא' });
  const { rating, comment, name } = req.body;
  const r = Math.max(1, Math.min(5, parseInt(rating) || 5));
  if (!ev.ratings) ev.ratings = [];
  ev.ratings.push({ rating: r, comment: sanitize(comment, 300), name: sanitize(name), createdAt: Date.now() });
  saveDB();
  res.json({ ok: true });
});

// ========== CATCH-ALL ==========
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ========== START ==========
const PORT = process.env.PORT || 3333;

(async () => {
  // Connect to MongoDB
  if (MONGO_URI) {
    const connected = await connectMongo();
    if (connected) {
      db = await loadDB();
      console.log(`MongoDB loaded: ${Object.keys(db.events || {}).length} events`);
    }
  } else {
    console.log('No MONGO_URI set — using file-based storage');
  }

  app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`  Event Gate Server running on port ${PORT}`);
    console.log(`  Admin Token: ${ADMIN_TOKEN}`);
    console.log(`  MongoDB: ${mongoConnected ? 'Connected ✓' : 'Not configured'}`);
    console.log(`========================================\n`);
  });
})();
