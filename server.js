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
    date: ev.date, slotCounts,
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

  // Colors
  const blue = { argb: 'FF3B82F6' };
  const green = { argb: 'FF22C55E' };
  const red = { argb: 'FFEF4444' };
  const yellow = { argb: 'FFEAB308' };
  const orange = { argb: 'FFF97316' };
  const darkBg = { argb: 'FF0F172A' };
  const cardBg = { argb: 'FF1E293B' };
  const headerBg = { argb: 'FF334155' };
  const white = { argb: 'FFF1F5F9' };

  const headerStyle = { font: { bold: true, color: white, size: 11 }, fill: { type: 'pattern', pattern: 'solid', fgColor: headerBg }, alignment: { horizontal: 'center', vertical: 'middle' }, border: { bottom: { style: 'thin', color: { argb: 'FF475569' } } } };
  const dataStyle = { alignment: { horizontal: 'right', vertical: 'middle' } };

  // ===== SHEET 1: Summary =====
  const ws1 = wb.addWorksheet('סיכום', { views: [{ rightToLeft: true }] });
  ws1.columns = [
    { width: 5 }, { width: 25 }, { width: 20 }, { width: 15 }, { width: 15 }, { width: 15 }, { width: 15 },
  ];

  // Title
  ws1.mergeCells('A1:G1');
  const titleCell = ws1.getCell('A1');
  titleCell.value = `🌈 ${evTitle}`;
  titleCell.font = { bold: true, size: 18, color: blue };
  titleCell.alignment = { horizontal: 'center', vertical: 'middle' };
  ws1.getRow(1).height = 35;

  ws1.mergeCells('A2:G2');
  ws1.getCell('A2').value = `${evDate} | ${timeRange}`;
  ws1.getCell('A2').font = { size: 12, color: green };
  ws1.getCell('A2').alignment = { horizontal: 'center' };

  ws1.mergeCells('A3:G3');
  ws1.getCell('A3').value = `איש קשר: ${ev.contactName || '-'} | ${ev.contactPhone || '-'} | כתובת: ${ev.eventAddress || '-'}`;
  ws1.getCell('A3').font = { size: 10, color: { argb: 'FF94A3B8' } };
  ws1.getCell('A3').alignment = { horizontal: 'center' };

  // Summary stats
  const preRegs = Object.values(ev.preRegs || {});
  const guests = Object.values(ev.guests || {});
  const waitlist = Object.values(ev.waitlist || {}).filter(w => w.status === 'waiting');
  const totalRegP = preRegs.reduce((s, r) => s + (r.participants || 1), 0);
  const arrivedP = preRegs.filter(r => r.arrived).reduce((s, r) => s + (r.participants || 1), 0);
  const notArrivedP = totalRegP - arrivedP;
  const walkinP = guests.filter(g => g.type === 'walkin').reduce((s, g) => s + (g.groupSize || 1), 0);
  const totalVisited = guests.reduce((s, g) => s + (g.groupSize || 1), 0);
  const activeP = guests.filter(g => !g.checkoutTime).reduce((s, g) => s + (g.groupSize || 1), 0);
  const waitlistP = waitlist.reduce((s, w) => s + (w.participants || 1), 0);
  const arrivalRate = totalRegP > 0 ? Math.round(arrivedP / totalRegP * 100) : 0;

  const stats = [
    ['נרשמו מראש (משתתפים)', totalRegP],
    ['הגיעו מרישום מוקדם', arrivedP],
    ['לא הגיעו', notArrivedP],
    ['אחוז הגעה', `${arrivalRate}%`],
    ['אורחים מזדמנים', walkinP],
    ['סה"כ ביקרו', totalVisited],
    ['נוכחים כרגע', activeP],
    ['ברשימת המתנה', waitlistP],
  ];

  ws1.addRow([]);
  const sumHeaderRow = ws1.addRow(['', 'סיכום מנכ"ל', '', 'ערך']);
  sumHeaderRow.eachCell((c, i) => { if (i > 1) Object.assign(c, headerStyle); });
  sumHeaderRow.height = 25;

  stats.forEach(([label, val]) => {
    const r = ws1.addRow(['', label, '', val]);
    r.getCell(2).font = { bold: true, size: 11 };
    r.getCell(4).font = { bold: true, size: 13, color: typeof val === 'string' && val.includes('%') ? (arrivalRate >= 50 ? green : red) : blue };
    r.getCell(4).alignment = { horizontal: 'center' };
  });

  // ===== SHEET 2: Registrations by Slot =====
  const ws2 = wb.addWorksheet('נרשמים לפי סבב', { views: [{ rightToLeft: true }] });
  ws2.columns = [
    { width: 5 }, { width: 22 }, { width: 16 }, { width: 12 }, { width: 16 }, { width: 12 },
  ];

  let rowNum = 1;
  slots.forEach((sl, i) => {
    const slotRegs = preRegs.filter(r => r.slotIndex === i).sort((a, b) => (a.registeredAt || 0) - (b.registeredAt || 0));
    const slotP = slotRegs.reduce((s, r) => s + (r.participants || 1), 0);
    const slotArrived = slotRegs.filter(r => r.arrived).reduce((s, r) => s + (r.participants || 1), 0);

    // Slot header
    const slotRow = ws2.addRow(['', `סבב ${i + 1}: ${sl.label}`, '', `${slotP}/${ev.maxCapacity}`, `${slotArrived} הגיעו`]);
    slotRow.eachCell((c) => {
      c.font = { bold: true, size: 12, color: white };
      c.fill = { type: 'pattern', pattern: 'solid', fgColor: blue };
      c.alignment = { horizontal: 'center', vertical: 'middle' };
    });
    slotRow.height = 28;

    // Column headers
    const hRow = ws2.addRow(['#', 'שם', 'טלפון', 'משתתפים', 'תאריך רישום', 'סטטוס']);
    hRow.eachCell((c) => Object.assign(c, headerStyle));

    if (slotRegs.length === 0) {
      ws2.addRow(['', 'אין נרשמים לסבב זה']);
    } else {
      slotRegs.forEach((r, idx) => {
        const regDate = r.registeredAt ? new Date(r.registeredAt).toLocaleString('he-IL', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '';
        const status = r.arrived ? '✓ הגיע/ה' : '✗ לא הגיע/ה';
        const row = ws2.addRow([idx + 1, r.name, r.phone || '', r.participants || 1, regDate, status]);
        row.getCell(6).font = { color: r.arrived ? green : red, bold: true };
      });
    }
    ws2.addRow([]); // spacer
  });

  // ===== SHEET 3: Walk-ins =====
  const ws3 = wb.addWorksheet('מזדמנים', { views: [{ rightToLeft: true }] });
  ws3.columns = [
    { width: 5 }, { width: 22 }, { width: 16 }, { width: 12 }, { width: 12 }, { width: 12 }, { width: 12 }, { width: 12 },
  ];

  const wkTitle = ws3.addRow(['', `אורחים מזדמנים (${walkinP} משתתפים)`]);
  wkTitle.getCell(2).font = { bold: true, size: 14, color: orange };
  wkTitle.height = 28;

  const wkHeader = ws3.addRow(['#', 'שם', 'טלפון', 'משתתפים', 'כניסה', 'יציאה', 'משך (דק\')', 'סטטוס']);
  wkHeader.eachCell((c) => Object.assign(c, headerStyle));

  const walkins = guests.filter(g => g.type === 'walkin').sort((a, b) => a.checkinTime - b.checkinTime);
  const now = Date.now();
  walkins.forEach((g, idx) => {
    const dur = g.checkoutTime ? Math.round((g.checkoutTime - g.checkinTime) / 60000) : Math.round((now - g.checkinTime) / 60000);
    const status = g.checkoutTime ? 'יצא/ה' : 'נוכח/ת';
    const exit = g.checkoutTime ? formatHM(g.checkoutTime) : '-';
    const row = ws3.addRow([idx + 1, g.name, g.phone || '', g.groupSize || 1, formatHM(g.checkinTime), exit, dur, status]);
    row.getCell(8).font = { color: g.checkoutTime ? { argb: 'FF94A3B8' } : green, bold: true };
  });
  if (walkins.length === 0) ws3.addRow(['', 'אין אורחים מזדמנים']);

  // ===== SHEET 4: Waitlist =====
  if (waitlist.length > 0) {
    const ws4 = wb.addWorksheet('רשימת המתנה', { views: [{ rightToLeft: true }] });
    ws4.columns = [{ width: 5 }, { width: 22 }, { width: 16 }, { width: 12 }, { width: 12 }, { width: 16 }];

    const wlTitle = ws4.addRow(['', `רשימת המתנה (${waitlistP} משתתפים)`]);
    wlTitle.getCell(2).font = { bold: true, size: 14, color: yellow };

    const wlHeader = ws4.addRow(['#', 'שם', 'טלפון', 'סבב', 'משתתפים', 'תאריך רישום']);
    wlHeader.eachCell((c) => Object.assign(c, headerStyle));

    waitlist.sort((a, b) => a.registeredAt - b.registeredAt).forEach((w, idx) => {
      const regDate = w.registeredAt ? new Date(w.registeredAt).toLocaleString('he-IL', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '';
      ws4.addRow([idx + 1, w.name, w.phone || '', `סבב ${w.slotIndex + 1}`, w.participants || 1, regDate]);
    });
  }

  // ===== SHEET 5: Insights (all events for this client) =====
  const clientEvents = Object.values(db.events).filter(e => e.clientName === ev.clientName).sort((a, b) => (a.startTime || 0) - (b.startTime || 0));
  if (clientEvents.length > 1) {
    const ws5 = wb.addWorksheet('תובנות לקוח', { views: [{ rightToLeft: true }] });
    ws5.columns = [{ width: 5 }, { width: 25 }, { width: 14 }, { width: 14 }, { width: 14 }, { width: 14 }, { width: 14 }, { width: 14 }];

    const insTitle = ws5.addRow(['', `תובנות — ${ev.clientName}`]);
    insTitle.getCell(2).font = { bold: true, size: 14, color: blue };

    const insHeader = ws5.addRow(['#', 'אירוע', 'תאריך', 'נרשמו', 'הגיעו', 'מזדמנים', 'סה"כ', 'אחוז הגעה']);
    insHeader.eachCell((c) => Object.assign(c, headerStyle));

    clientEvents.forEach((ce, idx) => {
      const ceRegs = Object.values(ce.preRegs || {});
      const ceGuests = Object.values(ce.guests || {});
      const ceRegP = ceRegs.reduce((s, r) => s + (r.participants || 1), 0);
      const ceArrivedP = ceRegs.filter(r => r.arrived).reduce((s, r) => s + (r.participants || 1), 0);
      const ceWalkinP = ceGuests.filter(g => g.type === 'walkin').reduce((s, g) => s + (g.groupSize || 1), 0);
      const ceTotal = ceGuests.reduce((s, g) => s + (g.groupSize || 1), 0);
      const ceRate = ceRegP > 0 ? `${Math.round(ceArrivedP / ceRegP * 100)}%` : '-';

      const row = ws5.addRow([idx + 1, ce.eventName || ce.clientName, ce.date || '', ceRegP, ceArrivedP, ceWalkinP, ceTotal, ceRate]);
      if (ce.id === ev.id) row.eachCell(c => { c.font = { ...c.font, bold: true, color: green }; });
    });
  }

  // Footer
  ws1.addRow([]);
  ws1.addRow(['', `הופק ב: ${new Date().toLocaleString('he-IL')}`]);
  ws1.addRow(['', '🌈 חברים של טופי בע"מ — ניהול זרימת קהל']);

  // Send file
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename=report_${ev.id}.xlsx`);
  await wb.xlsx.write(res);
  res.end();
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
