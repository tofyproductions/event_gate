process.env.TZ = 'Asia/Jerusalem';

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

// Normalize phone: +972 → 0, remove dashes/spaces, keep last 10 digits
function normalizePhone(phone) {
  if (!phone) return '';
  let p = phone.replace(/[^0-9]/g, '');
  if (p.startsWith('972') && p.length > 10) p = '0' + p.slice(3);
  return p.slice(-10);
}

function formatHM(ts) {
  return new Date(ts).toLocaleTimeString('he-IL', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Jerusalem' });
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
    date: ev.date,
    ended: (ev.slots && ev.slots.length > 0) ? Date.now() > ev.slots[ev.slots.length - 1].endTime : false,
    slotCounts,
    waitlistCounts: (() => {
      const wc = {};
      (ev.slots || []).forEach(s => { wc[s.index] = 0; });
      Object.values(ev.waitlist || {}).filter(w => w.status === 'waiting').forEach(w => {
        wc[w.slotIndex] = (wc[w.slotIndex] || 0) + (w.participants || 1);
      });
      return wc;
    })(),
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
  const startTime = new Date(`${date}T${time}:00+02:00`).getTime();
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
    guests: {}, preRegs: {}, waitlist: {}, createdAt: Date.now(),
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

  // Check if event has ended — block registration after last slot ends
  const slots = ev.slots || [];
  if (slots.length > 0) {
    const lastSlotEnd = slots[slots.length - 1].endTime;
    if (Date.now() > lastSlotEnd) {
      return res.status(400).json({ error: 'הרישום לאירוע זה נסגר — האירוע הסתיים' });
    }
  }

  const { name, phone, slotIndex, participants } = req.body;
  if (!name || name.trim().length === 0) return res.status(400).json({ error: 'נא להזין שם' });
  const cleanPhone = (phone || '').replace(/[^0-9]/g, '');
  if (!cleanPhone.match(/^05\d{8}$/)) return res.status(400).json({ error: 'מספר טלפון לא תקין — נדרש מספר ישראלי (05X) עם 10 ספרות' });

  // Check duplicate phone registration
  const normalNewPhone = normalizePhone(phone);
  const existingReg = Object.values(ev.preRegs).find(r => normalizePhone(r.phone) === normalNewPhone);
  if (existingReg) {
    return res.status(400).json({ error: 'מספר הטלפון כבר רשום לאירוע זה', existingCode: existingReg.code, existingSlot: existingReg.slotIndex, existingParticipants: existingReg.participants });
  }
  if (slotIndex === undefined || slotIndex < 0 || slotIndex >= ev.slots.length) {
    return res.status(400).json({ error: 'חלון זמן לא תקין' });
  }

  const pCount = Math.max(1, Math.min(4, parseInt(participants) || 1));
  const slotParticipants = Object.values(ev.preRegs).filter(r => r.slotIndex === slotIndex && r.status !== 'waitlist')
    .reduce((sum, r) => sum + (r.participants || 1), 0);

  const isFull = slotParticipants + pCount > ev.maxCapacity;
  const code = randomCode(6);

  // Check waitlist for duplicate phone too
  if (!ev.waitlist) ev.waitlist = {};
  const existingWaitlist = Object.values(ev.waitlist).find(w => w.status === 'waiting' && normalizePhone(w.phone) === normalNewPhone);
  if (existingWaitlist) {
    return res.status(400).json({ error: 'מספר הטלפון כבר רשום ברשימת ההמתנה לאירוע זה' });
  }

  if (isFull) {
    // Add to waitlist
    ev.waitlist[code] = {
      code, name: sanitize(name), phone: sanitize(phone, 20),
      registeredAt: Date.now(), slotIndex: parseInt(slotIndex),
      participants: pCount, status: 'waiting',
    };
    saveDB();
    return res.json({ code, slot: ev.slots[slotIndex], waitlist: true, position: Object.values(ev.waitlist).filter(w => w.slotIndex === slotIndex && w.status === 'waiting').length });
  }

  ev.preRegs[code] = {
    code, name: sanitize(name), phone: sanitize(phone, 20),
    registeredAt: Date.now(), arrived: false,
    slotIndex: parseInt(slotIndex), participants: pCount, status: 'confirmed',
  };
  saveDB();
  res.json({ code, slot: ev.slots[slotIndex], waitlist: false });
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
    const cleanPhone = (phone || '').replace(/[^0-9]/g, '');
  if (!cleanPhone.match(/^05\d{8}$/)) return res.status(400).json({ error: 'מספר טלפון לא תקין — נדרש מספר ישראלי (05X) עם 10 ספרות' });

    // Check if phone already exists in pre-regs or guests
    const normalPhone = normalizePhone(phone);
    const existingReg = Object.values(ev.preRegs).find(r => normalizePhone(r.phone) === normalPhone);
    if (existingReg) {
      return res.status(400).json({ error: `מספר הטלפון כבר רשום מראש (קוד: ${existingReg.code})` });
    }
    const existingGuest = Object.values(ev.guests).filter(g => !g.checkoutTime).find(g => normalizePhone(g.phone) === normalPhone);
    if (existingGuest) {
      return res.status(400).json({ error: 'מספר הטלפון כבר נמצא באירוע' });
    }

    const gs = Math.max(1, Math.min(20, parseInt(groupSize) || 1));
    const ac = activeCount(ev);
    // Admin can override capacity for walk-ins (not all pre-registered will show up)
    if (ac + gs > ev.maxCapacity && !req.query.override) {
      return res.status(400).json({ error: 'האירוע מלא', currentCount: ac, max: ev.maxCapacity, canOverride: true });
    }

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
    const normalPhone = normalizePhone(input);
    if (normalPhone.length >= 9) {
      const match = Object.entries(ev.preRegs).find(([, r]) => normalizePhone(r.phone) === normalPhone);
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

// Approve waitlist entry (admin) — moves from waitlist to preRegs
app.post('/api/events/:id/waitlist/:code/approve', requireAdmin, (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev) return res.status(404).json({ error: 'אירוע לא נמצא' });
  if (!ev.waitlist || !ev.waitlist[req.params.code]) return res.status(404).json({ error: 'ממתין לא נמצא' });
  const w = ev.waitlist[req.params.code];
  // Move to preRegs
  ev.preRegs[w.code] = {
    code: w.code, name: w.name, phone: w.phone,
    registeredAt: w.registeredAt, arrived: false,
    slotIndex: w.slotIndex, participants: w.participants, status: 'confirmed',
    approvedAt: Date.now(),
  };
  delete ev.waitlist[req.params.code];
  saveDB();
  res.json({ ok: true, reg: ev.preRegs[w.code] });
});

// Remove from waitlist (admin)
app.delete('/api/events/:id/waitlist/:code', requireAdmin, (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev) return res.status(404).json({ error: 'אירוע לא נמצא' });
  if (!ev.waitlist || !ev.waitlist[req.params.code]) return res.status(404).json({ error: 'ממתין לא נמצא' });
  delete ev.waitlist[req.params.code];
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
  const normalPhone = normalizePhone(phone);
  const entry = Object.entries(ev.preRegs).find(([, r]) => normalizePhone(r.phone) === normalPhone);
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

// ========== API: CLIENT AUTH BY PHONE ==========
app.post('/api/client-auth', (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'נא להזין מספר טלפון' });
  const np = normalizePhone(phone);
  if (np.length < 9) return res.status(400).json({ error: 'מספר טלפון לא תקין' });

  // Find all events where this phone is the contact
  const events = Object.values(db.events).filter(ev =>
    normalizePhone(ev.contactPhone) === np
  ).map(ev => {
    const preRegs = Object.values(ev.preRegs || {});
    const guests = Object.values(ev.guests || {});
    const ac = activeCount(ev);
    return {
      id: ev.id, clientName: ev.clientName, eventName: ev.eventName,
      date: ev.date, startTime: ev.startTime, clientToken: ev.clientToken,
      slots: ev.slots, numSlots: ev.numSlots, maxCapacity: ev.maxCapacity,
      attractions: ev.attractions, eventAddress: ev.eventAddress,
      activeCount: ac,
      totalGuests: guests.reduce((s, g) => s + (g.groupSize || 1), 0),
      totalRegs: preRegs.reduce((s, r) => s + (r.participants || 1), 0),
      pendingRegs: preRegs.filter(r => !r.arrived).reduce((s, r) => s + (r.participants || 1), 0),
      arrivedRegs: preRegs.filter(r => r.arrived).reduce((s, r) => s + (r.participants || 1), 0),
      walkins: guests.filter(g => g.type === 'walkin').reduce((s, g) => s + (g.groupSize || 1), 0),
      arrivalRate: preRegs.length > 0 ? Math.round(preRegs.filter(r => r.arrived).length / preRegs.length * 100) : 0,
    };
  });

  if (events.length === 0) return res.status(404).json({ error: 'לא נמצאו אירועים למספר זה' });
  res.json({ events });
});

// ========== API: XLSX EXPORT ==========
app.get('/api/events/:id/export', requireAdmin, async (req, res) => {
  const ExcelJS = require('exceljs');
  const ev = db.events[req.params.id];
  if (!ev) return res.status(404).json({ error: 'אירוע לא נמצא' });

  const wb = new ExcelJS.Workbook();
  wb.creator = 'חברים של טופי בע"מ';
  const evTitle = ev.eventName ? `${ev.eventName} — ${ev.clientName}` : ev.clientName;
  const evDate = ev.startTime ? new Date(ev.startTime).toLocaleDateString('he-IL', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }) : '';
  const slots = ev.slots || [];
  const timeRange = slots.length > 0 ? `${slots[0].label.split(' - ')[0]} - ${slots[slots.length - 1].label.split(' - ')[1]}` : '';

  // === COLORS ===
  const C = {
    brand: { argb: 'FF3B82F6' }, brandLight: { argb: 'FFDBEAFE' }, brandDark: { argb: 'FF1E40AF' },
    green: { argb: 'FF22C55E' }, greenLight: { argb: 'FFDCFCE7' }, greenDark: { argb: 'FF166534' },
    red: { argb: 'FFEF4444' }, redLight: { argb: 'FFFEE2E2' },
    yellow: { argb: 'FFEAB308' }, yellowLight: { argb: 'FFFEF9C3' },
    orange: { argb: 'FFF97316' }, orangeLight: { argb: 'FFFFEDD5' },
    purple: { argb: 'FFA855F7' }, purpleLight: { argb: 'FFF3E8FF' },
    gray: { argb: 'FF94A3B8' }, grayLight: { argb: 'FFF1F5F9' }, grayDark: { argb: 'FF334155' },
    white: { argb: 'FFFFFFFF' }, dark: { argb: 'FF0F172A' },
  };

  const border = (color = 'FFE2E8F0') => ({
    top: { style: 'thin', color: { argb: color } },
    bottom: { style: 'thin', color: { argb: color } },
    left: { style: 'thin', color: { argb: color } },
    right: { style: 'thin', color: { argb: color } },
  });

  // === DATA ===
  const preRegs = Object.values(ev.preRegs || {});
  const guests = Object.values(ev.guests || {});
  const waitlist = Object.values(ev.waitlist || {}).filter(w => w.status === 'waiting');
  const walkins = guests.filter(g => g.type === 'walkin');
  const preregGuests = guests.filter(g => g.type === 'preregistered');

  const totalRegP = preRegs.reduce((s, r) => s + (r.participants || 1), 0);
  const arrivedP = preRegs.filter(r => r.arrived).reduce((s, r) => s + (r.participants || 1), 0);
  const notArrivedP = totalRegP - arrivedP;
  const walkinP = walkins.reduce((s, g) => s + (g.groupSize || 1), 0);
  const totalVisited = guests.reduce((s, g) => s + (g.groupSize || 1), 0);
  const waitlistP = waitlist.reduce((s, w) => s + (w.participants || 1), 0);
  const arrivalRate = totalRegP > 0 ? Math.round(arrivedP / totalRegP * 100) : 0;

  const guestsWithDur = guests.filter(g => g.checkoutTime && g.checkinTime);
  const avgStayMin = guestsWithDur.length > 0 ? Math.round(guestsWithDur.reduce((s, g) => s + (g.checkoutTime - g.checkinTime), 0) / guestsWithDur.length / 60000) : 0;

  // Helper: styled section header
  function addSectionHeader(ws, text, color, row) {
    const r = ws.addRow([]);
    const r2 = ws.addRow(['', text]);
    r2.height = 32;
    r2.getCell(2).font = { bold: true, size: 14, color: C.white };
    for (let i = 1; i <= 11; i++) {
      r2.getCell(i).fill = { type: 'pattern', pattern: 'solid', fgColor: color };
      r2.getCell(i).border = border(color.argb);
    }
    return r2;
  }

  // Helper: styled table header
  function addTableHeader(ws, headers, color = C.grayDark) {
    const r = ws.addRow(headers);
    r.height = 26;
    r.eachCell((c) => {
      c.font = { bold: true, size: 10, color: C.white };
      c.fill = { type: 'pattern', pattern: 'solid', fgColor: color };
      c.alignment = { horizontal: 'center', vertical: 'middle' };
      c.border = border(color.argb);
    });
    return r;
  }

  // Helper: stat card in a row
  function addStatRow(ws, label, value, color, bgColor) {
    const r = ws.addRow(['', label, '', '', value]);
    r.height = 28;
    r.getCell(2).font = { bold: true, size: 11 };
    r.getCell(2).alignment = { vertical: 'middle' };
    r.getCell(5).font = { bold: true, size: 16, color: color };
    r.getCell(5).alignment = { horizontal: 'center', vertical: 'middle' };
    if (bgColor) {
      for (let i = 1; i <= 7; i++) {
        r.getCell(i).fill = { type: 'pattern', pattern: 'solid', fgColor: bgColor };
        r.getCell(i).border = border();
      }
    }
    return r;
  }

  // ============================================
  //  SHEET 1: DASHBOARD — Executive Summary
  // ============================================
  const ws1 = wb.addWorksheet('דשבורד מנכ"ל', { views: [{ rightToLeft: true }] });
  ws1.columns = [{ width: 3 }, { width: 28 }, { width: 16 }, { width: 16 }, { width: 16 }, { width: 16 }, { width: 16 }];

  // === Header Banner ===
  ws1.mergeCells('A1:G1');
  ws1.getRow(1).height = 10;
  for (let i = 1; i <= 7; i++) ws1.getCell(1, i).fill = { type: 'pattern', pattern: 'solid', fgColor: C.brand };

  ws1.mergeCells('A2:G2');
  ws1.getCell('A2').value = `🌈 ${evTitle}`;
  ws1.getCell('A2').font = { bold: true, size: 20, color: C.brandDark };
  ws1.getCell('A2').alignment = { horizontal: 'center', vertical: 'middle' };
  ws1.getRow(2).height = 40;

  ws1.mergeCells('A3:G3');
  ws1.getCell('A3').value = `📅 ${evDate}   |   🕐 ${timeRange}   |   📍 ${ev.eventAddress || '-'}`;
  ws1.getCell('A3').font = { size: 11, color: C.gray };
  ws1.getCell('A3').alignment = { horizontal: 'center' };
  ws1.getRow(3).height = 22;

  ws1.mergeCells('A4:G4');
  ws1.getCell('A4').value = `👤 ${ev.contactName || '-'}   |   📞 ${ev.contactPhone || '-'}`;
  ws1.getCell('A4').font = { size: 10, color: C.gray };
  ws1.getCell('A4').alignment = { horizontal: 'center' };

  ws1.mergeCells('A5:G5');
  ws1.getRow(5).height = 6;
  for (let i = 1; i <= 7; i++) ws1.getCell(5, i).fill = { type: 'pattern', pattern: 'solid', fgColor: C.brand };

  // === KPI Cards (2 rows of 3) ===
  ws1.addRow([]);
  const kpiRow1 = ws1.addRow(['', 'נרשמו מראש', '', 'הגיעו בפועל', '', 'אחוז הגעה']);
  kpiRow1.height = 20;
  kpiRow1.eachCell(c => { c.font = { size: 9, color: C.gray }; c.alignment = { horizontal: 'center' }; });

  const kpiVal1 = ws1.addRow(['', totalRegP, '', arrivedP, '', `${arrivalRate}%`]);
  kpiVal1.height = 38;
  kpiVal1.getCell(2).font = { bold: true, size: 28, color: C.brand };
  kpiVal1.getCell(2).alignment = { horizontal: 'center' };
  kpiVal1.getCell(2).fill = { type: 'pattern', pattern: 'solid', fgColor: C.brandLight };
  kpiVal1.getCell(2).border = border();

  kpiVal1.getCell(4).font = { bold: true, size: 28, color: C.green };
  kpiVal1.getCell(4).alignment = { horizontal: 'center' };
  kpiVal1.getCell(4).fill = { type: 'pattern', pattern: 'solid', fgColor: C.greenLight };
  kpiVal1.getCell(4).border = border();

  kpiVal1.getCell(6).font = { bold: true, size: 28, color: arrivalRate >= 50 ? C.green : arrivalRate >= 30 ? C.yellow : C.red };
  kpiVal1.getCell(6).alignment = { horizontal: 'center' };
  kpiVal1.getCell(6).fill = { type: 'pattern', pattern: 'solid', fgColor: arrivalRate >= 50 ? C.greenLight : arrivalRate >= 30 ? C.yellowLight : C.redLight };
  kpiVal1.getCell(6).border = border();

  ws1.addRow([]);
  const kpiRow2 = ws1.addRow(['', 'לא הגיעו', '', 'מזדמנים', '', 'סה"כ ביקרו']);
  kpiRow2.height = 20;
  kpiRow2.eachCell(c => { c.font = { size: 9, color: C.gray }; c.alignment = { horizontal: 'center' }; });

  const kpiVal2 = ws1.addRow(['', notArrivedP, '', walkinP, '', totalVisited]);
  kpiVal2.height = 38;
  kpiVal2.getCell(2).font = { bold: true, size: 28, color: C.red };
  kpiVal2.getCell(2).alignment = { horizontal: 'center' };
  kpiVal2.getCell(2).fill = { type: 'pattern', pattern: 'solid', fgColor: C.redLight };
  kpiVal2.getCell(2).border = border();

  kpiVal2.getCell(4).font = { bold: true, size: 28, color: C.orange };
  kpiVal2.getCell(4).alignment = { horizontal: 'center' };
  kpiVal2.getCell(4).fill = { type: 'pattern', pattern: 'solid', fgColor: C.orangeLight };
  kpiVal2.getCell(4).border = border();

  kpiVal2.getCell(6).font = { bold: true, size: 28, color: C.purple };
  kpiVal2.getCell(6).alignment = { horizontal: 'center' };
  kpiVal2.getCell(6).fill = { type: 'pattern', pattern: 'solid', fgColor: C.purpleLight };
  kpiVal2.getCell(6).border = border();

  // === Additional stats ===
  ws1.addRow([]);
  addStatRow(ws1, '⏱️ שהייה ממוצעת', avgStayMin > 0 ? `${avgStayMin} דקות` : '-', C.brand, C.grayLight);
  addStatRow(ws1, '⏳ ברשימת המתנה', `${waitlistP} משתתפים`, C.yellow, null);
  addStatRow(ws1, '📊 סבבים', `${slots.length} × ${ev.slotDurationMin || 30} דקות`, C.brand, C.grayLight);
  addStatRow(ws1, '🎯 תפוסה מקסימלית', `${ev.maxCapacity} לסבב`, C.brand, null);
  if (ev.attractions) addStatRow(ws1, '🎪 אטרקציות', ev.attractions.replace(/\n/g, ', '), C.brand, C.grayLight);

  // === Slot breakdown mini-table ===
  ws1.addRow([]);
  addSectionHeader(ws1, '📊 פירוט סבבים', C.brand);
  addTableHeader(ws1, ['', 'סבב', 'נרשמו', 'הגיעו', 'לא הגיעו', '% הגעה', 'תפוסה']);
  slots.forEach((sl, i) => {
    const slRegs = preRegs.filter(r => r.slotIndex === i);
    const slP = slRegs.reduce((s, r) => s + (r.participants || 1), 0);
    const slArr = slRegs.filter(r => r.arrived).reduce((s, r) => s + (r.participants || 1), 0);
    const slRate = slP > 0 ? Math.round(slArr / slP * 100) : 0;
    const pctFull = Math.round(slP / ev.maxCapacity * 100);

    const r = ws1.addRow(['', `${sl.label}`, slP, slArr, slP - slArr, `${slRate}%`, `${pctFull}%`]);
    r.eachCell((c, ci) => {
      c.alignment = { horizontal: 'center', vertical: 'middle' };
      c.border = border();
      if (ci > 1) c.fill = { type: 'pattern', pattern: 'solid', fgColor: i % 2 === 0 ? C.grayLight : C.white };
    });
    r.getCell(6).font = { bold: true, color: slRate >= 50 ? C.green : slRate >= 30 ? C.yellow : C.red };
    r.getCell(7).font = { bold: true, color: pctFull >= 90 ? C.red : pctFull >= 60 ? C.yellow : C.green };
  });

  // === Footer ===
  ws1.addRow([]); ws1.addRow([]);
  ws1.addRow(['', `הופק ב: ${new Date().toLocaleString('he-IL')}`]).getCell(2).font = { size: 9, color: C.gray };
  ws1.addRow(['', '🌈 חברים של טופי בע"מ — ניהול זרימת קהל']).getCell(2).font = { size: 10, color: C.brand, bold: true };

  // ============================================
  //  SHEET 2: Detailed Registration by Slot
  // ============================================
  const ws2 = wb.addWorksheet('פירוט נרשמים', { views: [{ rightToLeft: true }] });
  ws2.columns = [{ width: 5 }, { width: 24 }, { width: 16 }, { width: 12 }, { width: 18 }, { width: 14 }, { width: 14 }];

  // Title
  ws2.mergeCells('A1:G1');
  ws2.getCell('A1').value = `📋 פירוט נרשמים — ${evTitle}`;
  ws2.getCell('A1').font = { bold: true, size: 16, color: C.brandDark };
  ws2.getCell('A1').alignment = { horizontal: 'center' };
  ws2.getRow(1).height = 35;

  slots.forEach((sl, i) => {
    const slRegs = preRegs.filter(r => r.slotIndex === i).sort((a, b) => (a.registeredAt || 0) - (b.registeredAt || 0));
    const slP = slRegs.reduce((s, r) => s + (r.participants || 1), 0);
    const slArr = slRegs.filter(r => r.arrived).reduce((s, r) => s + (r.participants || 1), 0);
    const slRate = slP > 0 ? Math.round(slArr / slP * 100) : 0;

    // Slot header
    ws2.addRow([]);
    const sh = ws2.addRow(['', `סבב ${i + 1}: ${sl.label}`, `${slP}/${ev.maxCapacity} נרשמו`, `${slArr} הגיעו`, `${slP - slArr} לא הגיעו`, `${slRate}% הגעה`]);
    sh.height = 30;
    sh.eachCell(c => {
      c.font = { bold: true, size: 11, color: C.white };
      c.fill = { type: 'pattern', pattern: 'solid', fgColor: slRate >= 50 ? C.green : slRate >= 30 ? C.yellow : C.brand };
      c.alignment = { horizontal: 'center', vertical: 'middle' };
      c.border = border(C.brand.argb);
    });

    addTableHeader(ws2, ['#', 'שם', 'טלפון', 'משתתפים', 'תאריך רישום', 'סטטוס']);

    if (slRegs.length === 0) {
      const empty = ws2.addRow(['', 'אין נרשמים לסבב זה']);
      empty.getCell(2).font = { italic: true, color: C.gray };
    } else {
      // Arrived first, then not arrived
      const sorted = [...slRegs.filter(r => r.arrived), ...slRegs.filter(r => !r.arrived)];
      sorted.forEach((r, idx) => {
        const regDate = r.registeredAt ? new Date(r.registeredAt).toLocaleString('he-IL', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '';
        const status = r.arrived ? '✅ הגיע/ה' : '❌ לא הגיע/ה';
        const row = ws2.addRow([idx + 1, r.name, r.phone || '', r.participants || 1, regDate, status]);
        const bgCol = r.arrived ? C.greenLight : C.redLight;
        row.eachCell((c, ci) => {
          c.fill = { type: 'pattern', pattern: 'solid', fgColor: bgCol };
          c.border = border();
          c.alignment = { horizontal: ci <= 1 ? 'center' : 'right', vertical: 'middle' };
        });
        row.getCell(6).font = { bold: true, color: r.arrived ? C.greenDark : C.red };
      });
    }
  });

  // ============================================
  //  SHEET 3: Walk-ins
  // ============================================
  const ws3 = wb.addWorksheet('מזדמנים', { views: [{ rightToLeft: true }] });
  ws3.columns = [{ width: 5 }, { width: 24 }, { width: 16 }, { width: 12 }, { width: 14 }, { width: 14 }, { width: 12 }];

  ws3.mergeCells('A1:G1');
  ws3.getCell('A1').value = `🚶 אורחים מזדמנים — ${walkinP} משתתפים`;
  ws3.getCell('A1').font = { bold: true, size: 16, color: C.orange };
  ws3.getCell('A1').alignment = { horizontal: 'center' };
  ws3.getRow(1).height = 35;

  addTableHeader(ws3, ['#', 'שם', 'טלפון', 'משתתפים', 'כניסה', 'יציאה', 'משך (דק\')'], C.orange);

  const sortedWalkins = walkins.sort((a, b) => a.checkinTime - b.checkinTime);
  sortedWalkins.forEach((g, idx) => {
    const dur = g.checkoutTime ? Math.round((g.checkoutTime - g.checkinTime) / 60000) : '-';
    const row = ws3.addRow([idx + 1, g.name, g.phone || '', g.groupSize || 1, formatHM(g.checkinTime), g.checkoutTime ? formatHM(g.checkoutTime) : '-', dur]);
    row.eachCell((c) => {
      c.fill = { type: 'pattern', pattern: 'solid', fgColor: idx % 2 === 0 ? C.orangeLight : C.white };
      c.border = border();
      c.alignment = { horizontal: 'center', vertical: 'middle' };
    });
  });
  if (walkins.length === 0) {
    ws3.addRow(['', 'אין אורחים מזדמנים']).getCell(2).font = { italic: true, color: C.gray };
  }

  // ============================================
  //  SHEET 4: Waitlist
  // ============================================
  const ws4 = wb.addWorksheet('רשימת המתנה', { views: [{ rightToLeft: true }] });
  ws4.columns = [{ width: 5 }, { width: 24 }, { width: 16 }, { width: 12 }, { width: 12 }, { width: 18 }];

  ws4.mergeCells('A1:F1');
  ws4.getCell('A1').value = `⏳ רשימת המתנה — ${waitlistP} משתתפים`;
  ws4.getCell('A1').font = { bold: true, size: 16, color: C.yellow };
  ws4.getCell('A1').alignment = { horizontal: 'center' };
  ws4.getRow(1).height = 35;

  addTableHeader(ws4, ['#', 'שם', 'טלפון', 'סבב', 'משתתפים', 'תאריך רישום'], C.yellow);

  waitlist.sort((a, b) => (a.registeredAt || 0) - (b.registeredAt || 0)).forEach((w, idx) => {
    const regDate = w.registeredAt ? new Date(w.registeredAt).toLocaleString('he-IL', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '';
    const row = ws4.addRow([idx + 1, w.name, w.phone || '', `סבב ${(w.slotIndex || 0) + 1}`, w.participants || 1, regDate]);
    row.eachCell(c => {
      c.fill = { type: 'pattern', pattern: 'solid', fgColor: idx % 2 === 0 ? C.yellowLight : C.white };
      c.border = border();
      c.alignment = { horizontal: 'center', vertical: 'middle' };
    });
  });
  if (waitlist.length === 0) {
    ws4.addRow(['', 'אין ממתינים']).getCell(2).font = { italic: true, color: C.gray };
  }

  // ============================================
  //  SHEET 5: Client Insights — Cross-event
  // ============================================
  const clientEvents = Object.values(db.events).filter(e => e.clientName === ev.clientName).sort((a, b) => (a.startTime || 0) - (b.startTime || 0));

  const ws5 = wb.addWorksheet('תובנות והשוואה', { views: [{ rightToLeft: true }] });
  ws5.columns = [{ width: 5 }, { width: 26 }, { width: 14 }, { width: 12 }, { width: 12 }, { width: 12 }, { width: 12 }, { width: 12 }, { width: 12 }, { width: 12 }, { width: 12 }];

  ws5.mergeCells('A1:K1');
  ws5.getCell('A1').value = `📊 תובנות והשוואת אירועים — ${ev.clientName}`;
  ws5.getCell('A1').font = { bold: true, size: 18, color: C.brandDark };
  ws5.getCell('A1').alignment = { horizontal: 'center' };
  ws5.getRow(1).height = 40;

  ws5.mergeCells('A2:K2');
  ws5.getRow(2).height = 5;
  for (let i = 1; i <= 11; i++) ws5.getCell(2, i).fill = { type: 'pattern', pattern: 'solid', fgColor: C.brand };

  // Events comparison table
  ws5.addRow([]);
  addSectionHeader(ws5, '🔍 השוואת אירועים', C.brand);
  addTableHeader(ws5, ['#', 'אירוע', 'תאריך', 'נרשמו', 'הגיעו', 'לא הגיעו', 'מזדמנים', 'סה"כ', '% הגעה', 'המתנה', 'סבבים']);

  let allRegs = 0, allArrived = 0, allWalkins = 0, allTotal = 0, allWaitlist = 0;

  clientEvents.forEach((ce, idx) => {
    const ceRegs = Object.values(ce.preRegs || {});
    const ceGuests = Object.values(ce.guests || {});
    const ceRegP = ceRegs.reduce((s, r) => s + (r.participants || 1), 0);
    const ceArrivedP = ceRegs.filter(r => r.arrived).reduce((s, r) => s + (r.participants || 1), 0);
    const ceNotArrived = ceRegP - ceArrivedP;
    const ceWalkinP = ceGuests.filter(g => g.type === 'walkin').reduce((s, g) => s + (g.groupSize || 1), 0);
    const ceTotal = ceGuests.reduce((s, g) => s + (g.groupSize || 1), 0);
    const ceWaitP = Object.values(ce.waitlist || {}).filter(w => w.status === 'waiting').reduce((s, w) => s + (w.participants || 1), 0);
    const ceRate = ceRegP > 0 ? Math.round(ceArrivedP / ceRegP * 100) : 0;

    allRegs += ceRegP; allArrived += ceArrivedP; allWalkins += ceWalkinP; allTotal += ceTotal; allWaitlist += ceWaitP;

    const row = ws5.addRow([idx + 1, ce.eventName || ce.clientName, ce.date || '', ceRegP, ceArrivedP, ceNotArrived, ceWalkinP, ceTotal, `${ceRate}%`, ceWaitP, ce.numSlots || 0]);
    const isCurrent = ce.id === ev.id;
    row.eachCell((c, ci) => {
      c.alignment = { horizontal: 'center', vertical: 'middle' };
      c.border = border();
      c.fill = { type: 'pattern', pattern: 'solid', fgColor: isCurrent ? C.brandLight : (idx % 2 === 0 ? C.grayLight : C.white) };
      if (isCurrent) c.font = { bold: true, color: C.brand };
    });
    row.getCell(9).font = { bold: true, color: ceRate >= 50 ? C.green : ceRate >= 30 ? C.yellow : C.red };
  });

  // Totals row
  const allRate = allRegs > 0 ? Math.round(allArrived / allRegs * 100) : 0;
  const totRow = ws5.addRow(['', `סה"כ ${clientEvents.length} אירועים`, '', allRegs, allArrived, allRegs - allArrived, allWalkins, allTotal, `${allRate}%`, allWaitlist, '']);
  totRow.height = 30;
  totRow.eachCell(c => {
    c.font = { bold: true, size: 12, color: C.white };
    c.fill = { type: 'pattern', pattern: 'solid', fgColor: C.brand };
    c.alignment = { horizontal: 'center', vertical: 'middle' };
    c.border = border(C.brand.argb);
  });

  // === Insights Section ===
  ws5.addRow([]); ws5.addRow([]);
  addSectionHeader(ws5, '💡 תובנות אוטומטיות', C.purple);
  ws5.addRow([]);

  const avgVisitors = clientEvents.length > 0 ? Math.round(allTotal / clientEvents.length) : 0;
  const walkinPct = allTotal > 0 ? Math.round(allWalkins / allTotal * 100) : 0;

  // Best performing event
  let bestEvent = null, bestRate = 0;
  clientEvents.forEach(ce => {
    const r = Object.values(ce.preRegs || {});
    const rp = r.reduce((s, x) => s + (x.participants || 1), 0);
    const ap = r.filter(x => x.arrived).reduce((s, x) => s + (x.participants || 1), 0);
    const rate = rp > 0 ? Math.round(ap / rp * 100) : 0;
    if (rate > bestRate) { bestRate = rate; bestEvent = ce; }
  });

  const insights = [
    { icon: '📈', text: `ממוצע הגעה כללי: ${allRate}%`, color: allRate >= 50 ? C.green : C.red },
    { icon: '👥', text: `ממוצע מבקרים לאירוע: ${avgVisitors} משתתפים`, color: C.brand },
    { icon: '🚶', text: `${walkinPct}% מהמבקרים הם מזדמנים — ${walkinPct > 30 ? 'פוטנציאל גבוה לרישום מוקדם' : 'רוב המבקרים נרשמים מראש'}`, color: C.orange },
    allRate < 40 ? { icon: '⚠️', text: 'המלצה: שלחו תזכורות SMS/WhatsApp יום לפני האירוע להעלאת אחוז ההגעה', color: C.red } : { icon: '✅', text: 'אחוז הגעה טוב — המשיכו כך!', color: C.green },
    bestEvent ? { icon: '🏆', text: `האירוע המוביל: ${bestEvent.eventName || bestEvent.clientName} (${bestRate}% הגעה)`, color: C.green } : null,
    clientEvents.length >= 3 ? { icon: '📊', text: `נצברו ${clientEvents.length} אירועים — ניתן לזהות מגמות`, color: C.purple } : null,
    allWaitlist > 0 ? { icon: '⏳', text: `${allWaitlist} אנשים ברשימות המתנה — שקלו להגדיל קיבולת`, color: C.yellow } : null,
  ].filter(Boolean);

  insights.forEach((ins, idx) => {
    const r = ws5.addRow(['', `${ins.icon}  ${ins.text}`]);
    r.height = 24;
    r.getCell(2).font = { size: 11, color: ins.color };
    if (idx % 2 === 0) r.getCell(2).fill = { type: 'pattern', pattern: 'solid', fgColor: C.grayLight };
  });

  // === Footer ===
  ws5.addRow([]); ws5.addRow([]);
  const footerRow = ws5.addRow(['', `🌈 חברים של טופי בע"מ — הופק ב: ${new Date().toLocaleString('he-IL')}`]);
  footerRow.getCell(2).font = { size: 10, color: C.brand, bold: true };

  // Send file
  try {
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=report_${ev.eventName || ev.clientName}_${ev.date || ''}.xlsx`);
    await wb.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error('XLSX export error:', err);
    if (!res.headersSent) res.status(500).json({ error: 'שגיאה ביצוא הדוח: ' + err.message });
  }
});


// ========== VISUAL HTML REPORT ==========
app.get('/api/events/:id/report', requireAdmin, (req, res) => {
  const ev = db.events[req.params.id];
  if (!ev) return res.status(404).send('אירוע לא נמצא');

  const evTitle = ev.eventName ? `${ev.eventName} — ${ev.clientName}` : ev.clientName;
  const evDate = ev.startTime ? new Date(ev.startTime).toLocaleDateString('he-IL', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }) : '';
  const slots = ev.slots || [];
  const timeRange = slots.length > 0 ? `${slots[0].label.split(' - ')[0]} - ${slots[slots.length - 1].label.split(' - ')[1]}` : '';

  const preRegs = Object.values(ev.preRegs || {});
  const guests = Object.values(ev.guests || {});
  const waitlist = Object.values(ev.waitlist || {}).filter(w => w.status === 'waiting');
  const walkins = guests.filter(g => g.type === 'walkin');

  const totalRegP = preRegs.reduce((s, r) => s + (r.participants || 1), 0);
  const arrivedP = preRegs.filter(r => r.arrived).reduce((s, r) => s + (r.participants || 1), 0);
  const notArrivedP = totalRegP - arrivedP;
  const walkinP = walkins.reduce((s, g) => s + (g.groupSize || 1), 0);
  const totalVisited = guests.reduce((s, g) => s + (g.groupSize || 1), 0);
  const waitlistP = waitlist.reduce((s, w) => s + (w.participants || 1), 0);
  const arrivalRate = totalRegP > 0 ? Math.round(arrivedP / totalRegP * 100) : 0;
  const guestsWithDur = guests.filter(g => g.checkoutTime && g.checkinTime);
  const avgStayMin = guestsWithDur.length > 0 ? Math.round(guestsWithDur.reduce((s, g) => s + (g.checkoutTime - g.checkinTime), 0) / guestsWithDur.length / 60000) : 0;

  // Client cross-event data
  const clientEvents = Object.values(db.events).filter(e => e.clientName === ev.clientName).sort((a, b) => (a.startTime || 0) - (b.startTime || 0));

  // Build slot data
  const slotData = slots.map((sl, i) => {
    const sr = preRegs.filter(r => r.slotIndex === i);
    const sp = sr.reduce((s, r) => s + (r.participants || 1), 0);
    const sa = sr.filter(r => r.arrived).reduce((s, r) => s + (r.participants || 1), 0);
    return { label: sl.label, index: i, regs: sr, regP: sp, arrivedP: sa, rate: sp > 0 ? Math.round(sa / sp * 100) : 0 };
  });

  // Cross-event comparison
  const ceData = clientEvents.map(ce => {
    const r = Object.values(ce.preRegs || {}); const g = Object.values(ce.guests || {});
    const rp = r.reduce((s, x) => s + (x.participants || 1), 0);
    const ap = r.filter(x => x.arrived).reduce((s, x) => s + (x.participants || 1), 0);
    const wp = g.filter(x => x.type === 'walkin').reduce((s, x) => s + (x.groupSize || 1), 0);
    const tp = g.reduce((s, x) => s + (x.groupSize || 1), 0);
    return { id: ce.id, name: ce.eventName || ce.clientName, date: ce.date, regP: rp, arrivedP: ap, walkinP: wp, totalP: tp, rate: rp > 0 ? Math.round(ap / rp * 100) : 0, isCurrent: ce.id === ev.id };
  });

  const esc = s => (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  const html = `<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>דוח אירוע — ${esc(evTitle)}</title>
<style>
@page{size:A4;margin:10mm}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
.report{max-width:900px;margin:0 auto;padding:24px}
.no-print{margin:16px auto;max-width:900px;text-align:center;padding:12px}
.no-print button{padding:12px 32px;border:none;border-radius:12px;font-size:1rem;font-weight:700;cursor:pointer;color:white;margin:0 6px}
.btn-pdf{background:linear-gradient(135deg,#3b82f6,#2563eb)}
.btn-wa{background:linear-gradient(135deg,#22c55e,#16a34a)}

/* Header */
.header{background:linear-gradient(135deg,#1e3a5f,#0f172a);border-radius:20px;padding:28px;margin-bottom:20px;border:1px solid #1e40af;text-align:center;position:relative;overflow:hidden}
.header::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;background:linear-gradient(90deg,#ef4444,#f97316,#eab308,#22c55e,#3b82f6,#a855f7)}
.header h1{font-size:1.8rem;margin-bottom:6px;background:linear-gradient(135deg,#60a5fa,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .meta{font-size:.9rem;color:#94a3b8;margin-bottom:4px}
.header .meta b{color:#60a5fa}

/* KPI Cards */
.kpi-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}
.kpi{background:#1e293b;border-radius:16px;padding:20px 12px;text-align:center;border:1px solid #334155;position:relative;overflow:hidden}
.kpi::after{content:'';position:absolute;bottom:0;left:0;right:0;height:3px}
.kpi.blue::after{background:#3b82f6}.kpi.green::after{background:#22c55e}.kpi.red::after{background:#ef4444}
.kpi.orange::after{background:#f97316}.kpi.purple::after{background:#a855f7}.kpi.yellow::after{background:#eab308}
.kpi-val{font-size:2.4rem;font-weight:900;line-height:1.1}
.kpi-label{font-size:.75rem;color:#94a3b8;margin-top:4px}
.kpi.blue .kpi-val{color:#60a5fa}.kpi.green .kpi-val{color:#4ade80}.kpi.red .kpi-val{color:#f87171}
.kpi.orange .kpi-val{color:#fb923c}.kpi.purple .kpi-val{color:#c084fc}.kpi.yellow .kpi-val{color:#facc15}

/* Sections */
.section{background:#1e293b;border-radius:16px;padding:20px;margin-bottom:16px;border:1px solid #334155}
.section-title{font-size:1.1rem;font-weight:800;margin-bottom:14px;display:flex;align-items:center;gap:8px;padding-bottom:8px;border-bottom:2px solid #334155}

/* Slot bars */
.slot-bar{margin-bottom:10px;background:#0f172a;border-radius:10px;padding:12px;border:1px solid #334155}
.slot-header{display:flex;justify-content:space-between;margin-bottom:6px;font-size:.85rem}
.slot-fill{height:8px;border-radius:4px;transition:width .5s}
.slot-stats{display:flex;gap:16px;margin-top:6px;font-size:.75rem;color:#94a3b8}
.slot-stats b{color:#e2e8f0}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:.8rem;margin-top:10px}
th{background:#334155;color:#e2e8f0;padding:10px 8px;text-align:right;font-weight:700;font-size:.75rem}
td{padding:8px;border-bottom:1px solid #1e293b}
tr.arrived{background:rgba(34,197,94,.08)}
tr.arrived td:last-child{color:#4ade80;font-weight:700}
tr.notarrived{background:rgba(239,68,68,.05)}
tr.notarrived td:last-child{color:#f87171;font-weight:700}
tr.walkin{background:rgba(249,115,22,.06)}
tr.waitlist{background:rgba(234,179,8,.06)}

/* Chart bars */
.chart-bar{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.chart-label{width:120px;text-align:left;font-size:.75rem;color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chart-fill{height:24px;border-radius:6px;min-width:2px;position:relative;display:flex;align-items:center;justify-content:flex-end;padding:0 8px}
.chart-fill span{font-size:.7rem;font-weight:700;color:white}
.chart-track{flex:1;background:#0f172a;border-radius:6px;height:24px;overflow:hidden}

/* Insights */
.insight{padding:10px 14px;border-radius:10px;margin-bottom:8px;font-size:.85rem;display:flex;align-items:center;gap:8px}
.insight.good{background:rgba(34,197,94,.1);border-left:3px solid #22c55e}
.insight.warn{background:rgba(234,179,8,.1);border-left:3px solid #eab308}
.insight.bad{background:rgba(239,68,68,.1);border-left:3px solid #ef4444}
.insight.info{background:rgba(59,130,246,.1);border-left:3px solid #3b82f6}

/* Footer */
.footer{text-align:center;padding:20px;color:#475569;font-size:.75rem;border-top:1px solid #334155;margin-top:20px}
.footer .brand{font-size:.9rem;color:#60a5fa;font-weight:700}

@media print{
  body{background:white;color:#1e293b}
  .no-print{display:none}
  .report{padding:0}
  .header{background:linear-gradient(135deg,#eff6ff,#f0f9ff);border-color:#bfdbfe}
  .header h1{-webkit-text-fill-color:#1e40af}
  .section,.kpi{background:#f8fafc;border-color:#e2e8f0}
  th{background:#e2e8f0;color:#1e293b}
  td{border-color:#e2e8f0}
  .slot-bar{background:#f1f5f9;border-color:#e2e8f0}
}
</style>
</head>
<body>

<div class="no-print">
  <button class="btn-pdf" onclick="window.print()">🖨️ הדפס / שמור PDF</button>
  <button class="btn-wa" onclick="shareReport()">📲 שלח בוואצאפ</button>
</div>

<div class="report">

<!-- HEADER -->
<div class="header">
  <div style="font-size:.8rem;color:#94a3b8;margin-bottom:4px">דוח אירוע מפורט</div>
  <h1>🌈 ${esc(evTitle)}</h1>
  <div class="meta">📅 <b>${evDate}</b> &nbsp;|&nbsp; 🕐 <b>${timeRange}</b></div>
  <div class="meta">👤 ${esc(ev.contactName || '-')} &nbsp;|&nbsp; 📞 ${esc(ev.contactPhone || '-')} &nbsp;|&nbsp; 📍 ${esc(ev.eventAddress || '-')}</div>
  ${ev.attractions ? `<div class="meta" style="margin-top:6px">🎪 ${esc(ev.attractions).replace(/\n/g, ' • ')}</div>` : ''}
</div>

<!-- KPI CARDS -->
<div class="kpi-grid">
  <div class="kpi blue"><div class="kpi-val">${totalRegP}</div><div class="kpi-label">נרשמו מראש</div></div>
  <div class="kpi green"><div class="kpi-val">${arrivedP}</div><div class="kpi-label">הגיעו בפועל</div></div>
  <div class="kpi ${arrivalRate >= 50 ? 'green' : arrivalRate >= 30 ? 'yellow' : 'red'}"><div class="kpi-val">${arrivalRate}%</div><div class="kpi-label">אחוז הגעה</div></div>
</div>
<div class="kpi-grid">
  <div class="kpi red"><div class="kpi-val">${notArrivedP}</div><div class="kpi-label">לא הגיעו</div></div>
  <div class="kpi orange"><div class="kpi-val">${walkinP}</div><div class="kpi-label">מזדמנים</div></div>
  <div class="kpi purple"><div class="kpi-val">${totalVisited}</div><div class="kpi-label">סה"כ ביקרו</div></div>
</div>
<div class="kpi-grid" style="grid-template-columns:repeat(2,1fr)">
  <div class="kpi blue"><div class="kpi-val">${avgStayMin > 0 ? avgStayMin + ' דק\'' : '-'}</div><div class="kpi-label">שהייה ממוצעת</div></div>
  <div class="kpi yellow"><div class="kpi-val">${waitlistP}</div><div class="kpi-label">רשימת המתנה</div></div>
</div>

<!-- SLOT BREAKDOWN -->
<div class="section">
  <div class="section-title">📊 פירוט סבבים</div>
  ${slotData.map((sd, i) => {
    const pct = Math.round(sd.regP / ev.maxCapacity * 100);
    const fillColor = pct >= 90 ? '#ef4444' : pct >= 60 ? '#eab308' : '#22c55e';
    const ratePct = sd.rate;
    const rateColor = ratePct >= 50 ? '#4ade80' : ratePct >= 30 ? '#facc15' : '#f87171';
    return `<div class="slot-bar">
      <div class="slot-header"><span style="font-weight:700">סבב ${i + 1}: ${sd.label}</span><span style="color:${fillColor};font-weight:700">${sd.regP}/${ev.maxCapacity}</span></div>
      <div style="height:8px;background:#1e293b;border-radius:4px;overflow:hidden"><div style="height:100%;width:${pct}%;background:${fillColor};border-radius:4px"></div></div>
      <div class="slot-stats"><span>📋 נרשמו: <b>${sd.regP}</b></span><span>✅ הגיעו: <b style="color:${rateColor}">${sd.arrivedP}</b></span><span>❌ לא הגיעו: <b>${sd.regP - sd.arrivedP}</b></span><span>📈 הגעה: <b style="color:${rateColor}">${ratePct}%</b></span></div>
    </div>`;
  }).join('')}
</div>

<!-- REGISTRATIONS TABLE -->
<div class="section">
  <div class="section-title">📋 רשימת נרשמים מראש (${totalRegP} משתתפים)</div>
  ${slotData.map((sd, i) => `
    <div style="margin-bottom:16px">
      <div style="font-weight:700;font-size:.9rem;margin-bottom:6px;color:#60a5fa">סבב ${i + 1}: ${sd.label} (${sd.regP} משתתפים)</div>
      <table><tr><th>#</th><th>שם</th><th>טלפון</th><th>משתתפים</th><th>תאריך רישום</th><th>סטטוס</th></tr>
      ${[...sd.regs.filter(r => r.arrived), ...sd.regs.filter(r => !r.arrived)].map((r, idx) => {
        const regDate = r.registeredAt ? new Date(r.registeredAt).toLocaleString('he-IL', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '';
        return `<tr class="${r.arrived ? 'arrived' : 'notarrived'}"><td>${idx + 1}</td><td>${esc(r.name)}</td><td dir="ltr">${esc(r.phone || '')}</td><td>${r.participants || 1}</td><td>${regDate}</td><td>${r.arrived ? '✅ הגיע/ה' : '❌ לא הגיע/ה'}</td></tr>`;
      }).join('')}
      ${sd.regs.length === 0 ? '<tr><td colspan="6" style="text-align:center;color:#94a3b8">אין נרשמים</td></tr>' : ''}
      </table>
    </div>
  `).join('')}
</div>

<!-- WALK-INS -->
<div class="section">
  <div class="section-title">🚶 אורחים מזדמנים (${walkinP} משתתפים)</div>
  <table><tr><th>#</th><th>שם</th><th>טלפון</th><th>משתתפים</th><th>כניסה</th><th>יציאה</th><th>משך</th></tr>
  ${walkins.sort((a, b) => a.checkinTime - b.checkinTime).map((g, idx) => {
    const dur = g.checkoutTime ? Math.round((g.checkoutTime - g.checkinTime) / 60000) + ' דק\'' : '-';
    return `<tr class="walkin"><td>${idx + 1}</td><td>${esc(g.name)}</td><td dir="ltr">${esc(g.phone || '')}</td><td>${g.groupSize || 1}</td><td>${formatHM(g.checkinTime)}</td><td>${g.checkoutTime ? formatHM(g.checkoutTime) : '-'}</td><td>${dur}</td></tr>`;
  }).join('')}
  ${walkins.length === 0 ? '<tr><td colspan="7" style="text-align:center;color:#94a3b8">אין מזדמנים</td></tr>' : ''}
  </table>
</div>

<!-- WAITLIST -->
${waitlist.length > 0 ? `
<div class="section">
  <div class="section-title">⏳ רשימת המתנה (${waitlistP} משתתפים)</div>
  <table><tr><th>#</th><th>שם</th><th>טלפון</th><th>סבב</th><th>משתתפים</th></tr>
  ${waitlist.sort((a, b) => (a.registeredAt || 0) - (b.registeredAt || 0)).map((w, idx) =>
    `<tr class="waitlist"><td>${idx + 1}</td><td>${esc(w.name)}</td><td dir="ltr">${esc(w.phone || '')}</td><td>סבב ${(w.slotIndex || 0) + 1}</td><td>${w.participants || 1}</td></tr>`
  ).join('')}
  </table>
</div>` : ''}

<!-- CROSS-EVENT COMPARISON -->
${clientEvents.length > 1 ? `
<div class="section">
  <div class="section-title">📊 השוואת אירועים — ${esc(ev.clientName)}</div>

  <!-- Bar chart -->
  <div style="margin-bottom:20px">
    <div style="font-size:.85rem;font-weight:700;margin-bottom:10px;color:#94a3b8">סה"כ מבקרים לפי אירוע</div>
    ${ceData.map(ce => {
      const maxP = Math.max(...ceData.map(x => x.totalP), 1);
      const pct = Math.round(ce.totalP / maxP * 100);
      return `<div class="chart-bar">
        <div class="chart-label">${esc(ce.name)}</div>
        <div class="chart-track"><div class="chart-fill" style="width:${pct}%;background:${ce.isCurrent ? '#3b82f6' : '#475569'}"><span>${ce.totalP}</span></div></div>
      </div>`;
    }).join('')}
  </div>

  <!-- Comparison table -->
  <table><tr><th>#</th><th>אירוע</th><th>תאריך</th><th>נרשמו</th><th>הגיעו</th><th>מזדמנים</th><th>סה"כ</th><th>% הגעה</th></tr>
  ${ceData.map((ce, idx) => {
    const rateColor = ce.rate >= 50 ? '#4ade80' : ce.rate >= 30 ? '#facc15' : '#f87171';
    return `<tr style="${ce.isCurrent ? 'background:rgba(59,130,246,.15)' : ''}"><td>${idx + 1}</td><td style="${ce.isCurrent ? 'font-weight:700;color:#60a5fa' : ''}">${esc(ce.name)}</td><td>${ce.date}</td><td>${ce.regP}</td><td>${ce.arrivedP}</td><td>${ce.walkinP}</td><td style="font-weight:700">${ce.totalP}</td><td style="color:${rateColor};font-weight:700">${ce.rate}%</td></tr>`;
  }).join('')}
  </table>
</div>` : ''}

<!-- INSIGHTS -->
<div class="section">
  <div class="section-title">💡 תובנות</div>
  ${arrivalRate >= 50 ? '<div class="insight good">✅ אחוז הגעה טוב — המשיכו כך!</div>' : arrivalRate >= 30 ? '<div class="insight warn">⚠️ אחוז הגעה בינוני — שקלו לשלוח תזכורות לנרשמים</div>' : '<div class="insight bad">🔴 אחוז הגעה נמוך — מומלץ לשלוח תזכורות SMS/WhatsApp יום לפני</div>'}
  <div class="insight info">👥 ממוצע מבקרים: ${totalVisited} משתתפים</div>
  ${walkinP > 0 ? `<div class="insight info">🚶 ${Math.round(walkinP / Math.max(totalVisited, 1) * 100)}% מהמבקרים מזדמנים — ${walkinP > totalVisited * 0.3 ? 'פוטנציאל לרישום מוקדם גבוה יותר' : 'רוב המבקרים נרשמים מראש'}</div>` : ''}
  ${waitlistP > 0 ? `<div class="insight warn">⏳ ${waitlistP} אנשים ברשימת המתנה — שקלו להגדיל תפוסה או להוסיף סבבים</div>` : ''}
  ${avgStayMin > 0 ? `<div class="insight info">⏱️ שהייה ממוצעת: ${avgStayMin} דקות${avgStayMin < 15 ? ' — קצר, אולי כדאי להעשיר את התוכן' : ''}</div>` : ''}
  ${clientEvents.length > 1 ? `<div class="insight info">📊 ${clientEvents.length} אירועים ללקוח — ממוצע הגעה כללי: ${Math.round(ceData.reduce((s, c) => s + c.arrivedP, 0) / Math.max(ceData.reduce((s, c) => s + c.regP, 0), 1) * 100)}%</div>` : ''}
</div>

<!-- FOOTER -->
<div class="footer">
  <div class="brand">🌈 חברים של טופי בע"מ — ניהול זרימת קהל</div>
  <div>הופק ב: ${new Date().toLocaleString('he-IL')}</div>
</div>

</div>

<script>
function shareReport() {
  const url = window.location.href;
  const msg = 'דוח אירוע: ${esc(evTitle)}\\n${evDate} | ${timeRange}\\n\\nצפייה בדוח:\\n' + url + '\\n\\n🌈 חברים של טופי בע"מ';
  window.open('https://wa.me/?text=' + encodeURIComponent(msg), '_blank');
}
</script>
</body></html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

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

// (end of file)
