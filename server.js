require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');

const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json());

const JWT_SECRET  = process.env.JWT_SECRET;
const JWT_EXPIRES = '7d';

if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET is not set in .env — add it before starting the server.');
  process.exit(1);
}

/* ── UNIT SCHEMA (existing) ──────────────────────────── */
const unitSchema = new mongoose.Schema({
  name:      { type: String, required: true },
  price:     { type: Number, required: true },
  property:  { type: String, default: '' },
  tenant:    { type: String, default: '—' },
  floor:     { type: String, default: '—' },
  status:    { type: String, default: 'Vacant' },
  createdAt: { type: Date,   default: Date.now },
});

const Unit = mongoose.model('Product', unitSchema);

/* ── USER SCHEMA (new) ───────────────────────────────── */
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName:  { type: String, required: true },
  email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone:     { type: String, default: '' },
  role:      { type: String, required: true },
  password:  { type: String, required: true },
  avatar:    { type: String, default: '' },
  createdAt: { type: Date,   default: Date.now },
});

const User = mongoose.model('User', userSchema);

/* ══════════════════════════════════════════════════════
   AUTH MIDDLEWARE  (new)
══════════════════════════════════════════════════════ */

// Verifies the Bearer token and attaches { id, role } to req.user
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: 'No token provided.' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET); // { id, role, iat, exp }
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

// Restricts a route to specific roles. Use AFTER requireAuth.
// e.g. requireRole('agency-director', 'property-manager')
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'You do not have permission to perform this action.' });
    }
    next();
  };
}

/* ── ROLE GROUPS ──────────────────────────────────────
   These MUST match the exact role values used at signup
   (see auth.html's role dropdown). ─────────────────── */
const MANAGEMENT   = ['agency-director', 'property-manager'];               // full access, agency-wide
const FINANCE_VIEW  = ['agency-director', 'property-manager', 'finance-officer', 'auditor']; // can see payments
const FINANCE_WRITE = ['agency-director', 'property-manager', 'finance-officer'];             // can create/edit/delete payments (auditor is read-only)
const MAINT_WRITE  = ['agency-director', 'property-manager', 'maintenance-staff'];          // can update/delete work orders
const UNIT_WRITE   = ['agency-director', 'property-manager', 'leasing-agent'];               // can create/edit/delete units

// Helper: sign a token for a given user document
function signToken(user) {
  return jwt.sign(
    { id: user._id, role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

/* ══════════════════════════════════════════════════════
   AUTH ROUTES
══════════════════════════════════════════════════════ */

// POST /auth/register — create new user
app.post('/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, role, password } = req.body;

    if (!firstName || !lastName || !email || !role || !password) {
      return res.status(400).json({ message: 'All required fields must be filled.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters.' });
    }

    // Check if email already exists
    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    // Hash the password before saving — never store plain text
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ firstName, lastName, email, phone, role, password: hashedPassword });
    const saved = await user.save();

    const token = signToken(saved);

    // Return user without password
    const { password: _, ...safeUser } = saved.toObject();
    res.status(201).json({ message: '✅ Account created successfully!', user: safeUser, token });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /auth/login — sign in
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;

    if (!email || !password || !role) {
      return res.status(400).json({ message: 'Email, password and role are required.' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });

    if (!user) {
      return res.status(401).json({ message: 'No account found with that email address.' });
    }

    // Compare the submitted password against the stored value.
    // Accounts created before password hashing was added still have a
    // plain-text password in the database — detect that case and upgrade
    // it to a proper bcrypt hash transparently, instead of locking the user out.
    const storedPassword = user.password;
    const isBcryptHash = typeof storedPassword === 'string' && storedPassword.startsWith('$2');

    let passwordMatches = false;

    if (isBcryptHash) {
      passwordMatches = await bcrypt.compare(password, storedPassword);
    } else if (storedPassword === password) {
      // Legacy plain-text match — upgrade to a hash now that we've verified it
      passwordMatches = true;
      user.password = await bcrypt.hash(password, 10);
      await user.save();
    }

    if (!passwordMatches) {
      return res.status(401).json({ message: 'Incorrect password. Please try again.' });
    }

    if (user.role !== role) {
      return res.status(401).json({ message: `This account is registered as "${user.role}", not "${role}".` });
    }

    const token = signToken(user);

    const { password: _, ...safeUser } = user.toObject();
    res.json({ message: '✅ Login successful!', user: safeUser, token });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /auth/users — get all users (management only)
app.get('/auth/users', requireAuth, requireRole(...MANAGEMENT), async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /auth/users/:id — get single user (any authenticated user)
app.get('/auth/users/:id', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PUT /auth/users/:id — update user profile (any authenticated user, own record)
app.put('/auth/users/:id', requireAuth, async (req, res) => {
  try {
    // Only allow users to edit their own profile, unless they are management
    const isSelf = req.user.id === req.params.id;
    const isPrivileged = MANAGEMENT.includes(req.user.role);
    if (!isSelf && !isPrivileged) {
      return res.status(403).json({ message: 'You can only update your own profile.' });
    }

    const { firstName, lastName, phone, avatar, password, role } = req.body;
    const updateData = { firstName, lastName, phone, avatar };

    // Only management may change roles
    if (role && isPrivileged) updateData.role = role;

    // Re-hash password if it's being changed
    if (password && password.length >= 8) {
      updateData.password = await bcrypt.hash(password, 10);
    }

    const updated = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    ).select('-password');

    if (!updated) return res.status(404).json({ message: 'User not found' });
    res.json({ message: '✅ Profile updated!', user: updated });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE /auth/users/:id — delete account (self, or management)
app.delete('/auth/users/:id', requireAuth, async (req, res) => {
  try {
    const isSelf = req.user.id === req.params.id;
    const isPrivileged = MANAGEMENT.includes(req.user.role);
    if (!isSelf && !isPrivileged) {
      return res.status(403).json({ message: 'You do not have permission to delete this account.' });
    }

    await User.findByIdAndDelete(req.params.id);
    res.json({ message: '✅ Account deleted successfully.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ══════════════════════════════════════════════════════
   UNIT ROUTES  (now protected)
══════════════════════════════════════════════════════ */

app.get('/', (req, res) => {
  res.json({ message: '✅ Meridian Properties API running!' });
});

app.get('/products', requireAuth, async (req, res) => {
  try {
    let query = {};

    if (req.user.role === 'maintenance-staff') {
      // Maintenance staff only need to see units that actually need work
      query = { status: 'Maintenance' };
    } else if (req.user.role === 'tenant') {
      // A tenant should only see their own unit, not the whole portfolio
      const me = await User.findById(req.user.id);
      if (!me) return res.status(404).json({ message: 'User not found' });
      const fullName = `${me.firstName} ${me.lastName}`.trim();
      query = { tenant: fullName };
    }
    // agency-director, property-manager, leasing-agent, finance-officer, auditor → agency-wide (no filter)

    const units = await Unit.find(query).sort({ createdAt: -1 });
    res.json(units);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/products', requireAuth, requireRole(...UNIT_WRITE), async (req, res) => {
  try {
    const unit = new Unit({
      name:     req.body.name,
      price:    req.body.price,
      property: req.body.property || '',
      tenant:   req.body.tenant   || '—',
      floor:    req.body.floor    || '—',
      status:   req.body.status   || 'Vacant',
    });
    const saved = await unit.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/products/:id', requireAuth, requireRole(...UNIT_WRITE), async (req, res) => {
  try {
    const updated = await Unit.findByIdAndUpdate(
      req.params.id,
      { name: req.body.name, price: req.body.price, property: req.body.property, tenant: req.body.tenant, floor: req.body.floor, status: req.body.status },
      { new: true }
    );
    if (!updated) return res.status(404).json({ message: 'Unit not found' });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/products/:id', requireAuth, requireRole(...UNIT_WRITE), async (req, res) => {
  try {
    await Unit.findByIdAndDelete(req.params.id);
    res.json({ message: '✅ Unit deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ── MAINTENANCE SCHEMA ──────────────────────────────── */
const maintenanceSchema = new mongoose.Schema({
  title:       { type: String, required: true },
  category:    { type: String, default: '' },
  property:    { type: String, default: '' },
  unit:        { type: String, default: '' },
  priority:    { type: String, default: 'Medium' },
  status:      { type: String, default: 'Open' },
  assignedTo:  { type: String, default: '' },
  description: { type: String, default: '' },
  createdAt:   { type: Date,   default: Date.now },
});

const Maintenance = mongoose.model('Maintenance', maintenanceSchema);

/* ── MAINTENANCE ROUTES  (now protected) ─────────────── */

// GET all work orders — any authenticated user
app.get('/maintenance', requireAuth, async (req, res) => {
  try {
    const orders = await Maintenance.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST — create work order — any authenticated user (e.g. a tenant reporting an issue)
app.post('/maintenance', requireAuth, async (req, res) => {
  try {
    const order = new Maintenance({
      title:       req.body.title,
      category:    req.body.category    || '',
      property:    req.body.property    || '',
      unit:        req.body.unit        || '',
      priority:    req.body.priority    || 'Medium',
      status:      req.body.status      || 'Open',
      assignedTo:  req.body.assignedTo  || '',
      description: req.body.description || '',
    });
    const saved = await order.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PUT — update work order (status, assignee, etc.) — management or maintenance staff
app.put('/maintenance/:id', requireAuth, requireRole(...MAINT_WRITE), async (req, res) => {
  try {
    const updated = await Maintenance.findByIdAndUpdate(
      req.params.id,
      {
        title:       req.body.title,
        category:    req.body.category,
        property:    req.body.property,
        unit:        req.body.unit,
        priority:    req.body.priority,
        status:      req.body.status,
        assignedTo:  req.body.assignedTo,
        description: req.body.description,
      },
      { new: true }
    );
    if (!updated) return res.status(404).json({ message: 'Work order not found' });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE — remove work order — management or maintenance staff
app.delete('/maintenance/:id', requireAuth, requireRole(...MAINT_WRITE), async (req, res) => {
  try {
    await Maintenance.findByIdAndDelete(req.params.id);
    res.json({ message: '✅ Work order deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ── PAYMENT SCHEMA ──────────────────────────────────── */
const paymentSchema = new mongoose.Schema({
  tenant:    { type: String, required: true }, // display name — kept for backward compatibility & quick display
  tenantId:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // real link to the User record
  property:  { type: String, default: '' },
  unit:      { type: String, default: '' },
  amount:    { type: Number, required: true },
  type:      { type: String, default: 'Rent' },
  status:    { type: String, default: 'Paid' },
  method:    { type: String, default: 'M-Pesa' },
  date:      { type: Date,   default: Date.now },
  reference: { type: String, default: '' },
  createdAt: { type: Date,   default: Date.now },
});

const Payment = mongoose.model('Payment', paymentSchema);

/* ── PAYMENT ROUTES  (now protected — owner/manager only) ─ */

// GET all payments — finance-capable roles see everything; a tenant sees only their own records
app.get('/payments', requireAuth, async (req, res) => {
  try {
    let query = {};

    if (req.user.role === 'tenant') {
      // Preferred: match by the real tenantId reference.
      // Fallback: some older payment records may pre-date the tenantId field
      // and only have the tenant's name stored as text — match on that too
      // so a tenant doesn't lose visibility of payments recorded before the change.
      const me = await User.findById(req.user.id);
      if (!me) return res.status(404).json({ message: 'User not found' });
      const fullName = `${me.firstName} ${me.lastName}`.trim();

      query = {
        $or: [
          { tenantId: me._id },
          { tenantId: null, tenant: fullName },
        ],
      };
    } else if (!FINANCE_VIEW.includes(req.user.role)) {
      // Roles like maintenance-staff / leasing-agent have no business reason
      // to see tenant financial records
      return res.status(403).json({ message: 'You do not have permission to view payment records.' });
    }

    const payments = await Payment.find(query).sort({ createdAt: -1 });
    res.json(payments);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST — record a payment
app.post('/payments', requireAuth, requireRole(...FINANCE_WRITE), async (req, res) => {
  try {
    let tenantName = req.body.tenant;
    let tenantId   = req.body.tenantId || null;

    // If a tenantId was supplied, look up the user and use their real name —
    // this keeps `tenant` (display text) and `tenantId` (real link) in sync.
    if (tenantId) {
      const tenantUser = await User.findById(tenantId);
      if (!tenantUser) {
        return res.status(400).json({ message: 'Selected tenant account was not found.' });
      }
      tenantName = `${tenantUser.firstName} ${tenantUser.lastName}`.trim();
    }

    if (!tenantName) {
      return res.status(400).json({ message: 'A tenant name or tenantId is required.' });
    }

    const payment = new Payment({
      tenant:    tenantName,
      tenantId:  tenantId,
      property:  req.body.property  || '',
      unit:      req.body.unit      || '',
      amount:    req.body.amount,
      type:      req.body.type      || 'Rent',
      status:    req.body.status    || 'Paid',
      method:    req.body.method    || 'M-Pesa',
      date:      req.body.date      || new Date(),
      reference: req.body.reference || '',
    });
    const saved = await payment.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PUT — update a payment record
app.put('/payments/:id', requireAuth, requireRole(...FINANCE_WRITE), async (req, res) => {
  try {
    let tenantName = req.body.tenant;
    let tenantId   = req.body.tenantId;

    if (tenantId) {
      const tenantUser = await User.findById(tenantId);
      if (!tenantUser) {
        return res.status(400).json({ message: 'Selected tenant account was not found.' });
      }
      tenantName = `${tenantUser.firstName} ${tenantUser.lastName}`.trim();
    }

    const updateData = {
      tenant:    tenantName,
      property:  req.body.property,
      unit:      req.body.unit,
      amount:    req.body.amount,
      type:      req.body.type,
      status:    req.body.status,
      method:    req.body.method,
      date:      req.body.date,
      reference: req.body.reference,
    };
    // Only touch tenantId if the client actually sent one
    if (tenantId !== undefined) updateData.tenantId = tenantId;

    const updated = await Payment.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    );
    if (!updated) return res.status(404).json({ message: 'Payment not found' });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE — remove a payment record
app.delete('/payments/:id', requireAuth, requireRole(...FINANCE_WRITE), async (req, res) => {
  try {
    await Payment.findByIdAndDelete(req.params.id);
    res.json({ message: '✅ Payment deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

/* ── CONNECT & START ─────────────────────────────────── */
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB');
    app.listen(3000, () => {
      console.log('✅ Server running on port 3000');
    });
  })
  .catch(err => console.error('❌ MongoDB error:', err.message));