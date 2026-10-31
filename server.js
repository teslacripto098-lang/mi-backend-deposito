const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { hash, limitAttempts, recoveryMailer, processResetJobs, Attempt, ResetJob } = require('./security');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    sessionVersion: { type: Number, default: 0 },
    resetTokenHash: { type: String, select: false },
    resetTokenExpiresAt: { type: Date, select: false },
    balance: { type: Number, default: 0 },
    vipLevel: { type: Number, default: 1, min: 1, max: 3600 },
    taskCompletedToday: { type: Boolean, default: false },
    lastTaskDay: { type: String, default: null },
    isBlocked: { type: Boolean, default: false },
    withdrawRestricted: { type: Boolean, default: false },
    role: { type: String, default: 'client' }
});
const User = mongoose.model('User', UserSchema);
const Transaction = mongoose.model('Transaction', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: String,
    amount: Number,
    uniqueWalletCode: String,
    status: { type: String, default: 'PENDING' },
    createdAt: { type: Date, default: Date.now }
}));

function taskDay(date, timeZone) {
    const parts = new Intl.DateTimeFormat('en-US', {
        timeZone, year: 'numeric', month: '2-digit', day: '2-digit'
    }).formatToParts(date);
    const value = type => parts.find(part => part.type === type).value;
    return `${value('year')}-${value('month')}-${value('day')}`;
}

function createApp({ secret = process.env.JWT_SECRET,
    timeZone = process.env.TASK_TIMEZONE || 'America/Mexico_City',
    clock = () => new Date(), sendReset = recoveryMailer(),
    trustProxyHops = Number(process.env.TRUST_PROXY_HOPS || 0) } = {}) {
    if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) {
        throw new Error('JWT_SECRET debe contener al menos 32 bytes.');
    }
    taskDay(clock(), timeZone); // Validar la zona horaria al iniciar.
    const app = express();
    if (!Number.isInteger(trustProxyHops) || trustProxyHops < 0 || trustProxyHops > 1) throw new Error('TRUST_PROXY_HOPS debe ser 0 o 1.');
    app.set('trust proxy', trustProxyHops);
    app.disable('x-powered-by');
    const origins = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
    app.use(cors({ origin: (origin, done) => done(null, !origin || origins.length === 0 || origins.includes(origin)) }));
    app.use(express.json({ limit: '16kb' }));
    app.use((req, res, next) => {
        res.set('Cache-Control', 'no-store');
        next();
    });
    const asyncRoute = handler => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
    const today = () => taskDay(clock(), timeZone);
    const publicUser = user => ({
        id: String(user._id), name: user.name, email: user.email,
        balance: user.balance, vipLevel: user.vipLevel, role: user.role,
        taskCompletedToday: user.lastTaskDay === today(),
        withdrawRestricted: user.withdrawRestricted
    });
    const emailValue = input => typeof input === 'string' ? input.trim().toLowerCase() : '';
    const validEmail = email => email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    const validPassword = value => typeof value === 'string' && value.length >= 8 && Buffer.byteLength(value) <= 72;
    const tokenOptions = { algorithm: 'HS256', issuer: 'mi-backend-deposito', audience: 'mi-backend-deposito-web' };

    const requireAuth = asyncRoute(async (req, res, next) => {
        const match = /^Bearer ([^\s]+)$/i.exec(req.get('Authorization') || '');
        if (!match) return res.status(401).json({ error: 'Debes iniciar sesión.' });
        let payload;
        try {
            payload = jwt.verify(match[1], secret, {
                algorithms: ['HS256'], issuer: tokenOptions.issuer, audience: tokenOptions.audience
            });
        } catch {
            return res.status(401).json({ error: 'Sesión inválida o vencida.' });
        }
        if (typeof payload !== 'object' || !mongoose.isObjectIdOrHexString(payload.sub)) {
            return res.status(401).json({ error: 'Sesión inválida.' });
        }
        const user = await User.findById(payload.sub);
        if (!user) return res.status(401).json({ error: 'Sesión inválida.' });
        if ((payload.ver ?? 0) !== (user.sessionVersion ?? 0)) return res.status(401).json({ error: 'La contraseña cambió. Inicia sesión nuevamente.' });
        if (user.isBlocked) return res.status(403).json({ error: 'Tu cuenta está bloqueada.' });
        req.user = user;
        next();
    });

    app.get('/health', (req, res) => {
        const connected = mongoose.connection.readyState === 1;
        res.status(connected ? 200 : 503).json({ status: connected ? 'ok' : 'unavailable' });
    });
    app.post('/api/register', limitAttempts('register-ip', 10, { clock }), asyncRoute(async (req, res) => {
        const { name, password } = req.body || {};
        const email = emailValue(req.body?.email);
        if (typeof name !== 'string' || !name.trim() || name.trim().length > 100 || !validEmail(email) || !validPassword(password)) {
            return res.status(400).json({ error: 'Indica nombre, correo válido y contraseña de al menos 8 caracteres y hasta 72 bytes.' });
        }
        // Comparacion insensible a mayusculas para respetar usuarios anteriores.
        const existing = await User.findOne({ email }).collation({ locale: 'en', strength: 2 });
        if (existing) return res.status(409).json({ error: 'El correo ya está registrado.' });
        const user = await User.create({ name: name.trim(), email, password: await bcrypt.hash(password, 12) });
        res.status(201).json({ message: 'Usuario registrado con éxito', user: publicUser(user) });
    }));
    app.post('/api/login', limitAttempts('login-ip', 30, { clock }), limitAttempts('login-account', 10, { account: true, clock }), asyncRoute(async (req, res) => {
        const email = emailValue(req.body?.email);
        const password = req.body?.password;
        if (!validEmail(email) || typeof password !== 'string' || !password || Buffer.byteLength(password) > 72) {
            return res.status(400).json({ error: 'Indica correo y contraseña válidos.' });
        }
        const user = await User.findOne({ email }).collation({ locale: 'en', strength: 2 }).select('+password');
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }
        if (user.isBlocked) return res.status(403).json({ error: 'Tu cuenta está bloqueada.' });
        const token = jwt.sign({ ver: user.sessionVersion ?? 0 }, secret, { ...tokenOptions, subject: String(user._id), expiresIn: '24h' });
        res.json({ token, tokenType: 'Bearer', expiresIn: 86400, role: user.role, user: publicUser(user) });
    }));
    app.get('/api/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

    app.post('/api/forgot-password', limitAttempts('forgot-ip', 10, { clock }), limitAttempts('forgot-account', 3, { account: true, clock }), asyncRoute(async (req, res) => {
        const email = emailValue(req.body?.email);
        if (!validEmail(email)) return res.status(400).json({ error: 'Indica un correo válido.' });
        if (!sendReset) return res.status(503).json({ error: 'La recuperación por correo aún no está configurada.' });
        // Encolar todos los correos validos produce la misma respuesta sin revelar cuentas.
        await ResetJob.create({ email, nextAttemptAt: clock(), expiresAt: new Date(clock().getTime()+3600000) });
        res.status(202).json({ message: 'Si el correo corresponde a una cuenta habilitada, recibirás un enlace para restablecer tu contraseña.' });
    }));
    app.post('/api/reset-password', limitAttempts('reset-ip', 20, { clock }), asyncRoute(async (req, res) => {
        const { token, password } = req.body || {};
        if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token) || !validPassword(password)) {
            return res.status(400).json({ error: 'Indica un enlace válido y una contraseña de al menos 8 caracteres y hasta 72 bytes.' });
        }
        const filter = { resetTokenHash: hash(token), resetTokenExpiresAt: { $gt: clock() }, isBlocked: false };
        if (!await User.exists(filter)) return res.status(400).json({ error: 'El enlace no es válido o ya venció.' });
        const passwordHash = await bcrypt.hash(password, 12);
        // Consumir enlace, cambiar clave e invalidar sesiones en una sola operacion.
        const result = await User.updateOne(filter, {
            $set: { password: passwordHash }, $inc: { sessionVersion: 1 },
            $unset: { resetTokenHash: '', resetTokenExpiresAt: '' }
        });
        if (!result.modifiedCount) return res.status(400).json({ error: 'El enlace no es válido o ya venció.' });
        res.json({ message: 'Contraseña actualizada. Inicia sesión con tu nueva contraseña.' });
    }));

    app.post('/api/complete-task', requireAuth, asyncRoute(async (req, res) => {
        if (req.body?.userId !== undefined) {
            return res.status(400).json({ error: 'No envíes userId: se obtiene de tu sesión.' });
        }
        const day = today();
        // Filtro y abono en una sola operacion: solicitudes simultaneas no duplican saldo.
        const user = await User.findOneAndUpdate({
            _id: req.user._id, isBlocked: false,
            vipLevel: { $gte: 1, $lte: 3600 },
            $or: [{ lastTaskDay: null }, { lastTaskDay: { $lt: day } }]
        }, [{ $set: {
            balance: { $add: ['$balance', { $add: [5, { $multiply: ['$vipLevel', 1.5] }] }] },
            lastTaskDay: day, taskCompletedToday: true
        } }], { new: true });
        if (!user) {
            const current = await User.findById(req.user._id);
            if (!current) return res.status(401).json({ error: 'Sesión inválida.' });
            if (current.isBlocked) return res.status(403).json({ error: 'Tu cuenta está bloqueada.' });
            return res.status(409).json({ error: 'La tarea ya fue completada hoy o no está disponible.' });
        }
        res.json({ success: true, newBalance: user.balance, reward: 5 + user.vipLevel * 1.5,
            taskDay: day, timeZone, user: publicUser(user) });
    }));

    // La integracion de pagos existente se conserva; requiere revision antes de uso real.
app.post('/api/webhook/payment', async (req, res) => {
    try {
        const { payment_id, order_id, payment_status, pay_amount, uniqueWalletCode } = req.body;

        // Verificar si el pago fue completado exitosamente en la pasarela
        if (payment_status === 'finished' || payment_status === 'confirmed') {
            const transaction = await Transaction.findOne({ uniqueWalletCode, status: 'PENDING' });
            if (!transaction) return res.status(404).json({ error: 'Transacción no encontrada o ya procesada' });

            // Actualizar estado de la transacción
            transaction.status = 'COMPLETED';
            await transaction.save();

            // Acreditar fondos automáticamente al usuario
            const user = await User.findById(transaction.userId);
            if (user) {
                user.balance += pay_amount;
                await user.save();
            }

            return res.json({ success: true, message: 'Pago acreditado automáticamente con éxito' });
        }

        res.status(400).json({ status: 'Pago pendiente o no confirmado' });
    } catch (err) {
        res.status(500).json({ error: 'Error procesando el webhook de pago' });
    }
});


    app.use((req, res) => res.status(404).json({ error: 'Ruta no encontrada.' }));
    app.use((err, req, res, next) => {
        if (err.code === 11000) return res.status(409).json({ error: 'El correo ya está registrado.' });
        if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Solicitud demasiado grande.' });
        if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'El cuerpo debe contener JSON válido.' });
        // No registrar cuerpos, credenciales ni cadenas de conexion.
        console.error('Error de solicitud:', err.name);
        res.status(500).json({ error: 'Error interno del servidor.' });
    });
    return app;
}

async function migrateLegacyTasks(day) {
    // No permitir otro cobro hoy a quienes ya completaron una tarea antes del cambio.
    await User.updateMany({ taskCompletedToday: true, lastTaskDay: null }, { $set: { lastTaskDay: day } });
}

async function start() {
    const app = createApp();
    if (!process.env.MONGO_URI) throw new Error('Falta configurar MONGO_URI.');
    await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 15000 });
    await User.init();
    await Promise.all([Attempt.init(), ResetJob.init()]);
    await migrateLegacyTasks(taskDay(new Date(), process.env.TASK_TIMEZONE || 'America/Mexico_City'));
    console.log('Conectado exitosamente a MongoDB');
    const server = app.listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('Servidor Backend iniciado'));
    const sendReset = recoveryMailer();
    let processing = false;
    const resetTimer = sendReset ? setInterval(async () => {
        if (processing) return;
        processing = true;
        try { await processResetJobs({ User, sendReset }); }
        catch { console.error('No se pudo procesar la cola de recuperación.'); }
        finally { processing = false; }
    }, 2000) : null;
    resetTimer?.unref();
    const shutdown = () => {
        if (resetTimer) clearInterval(resetTimer);
        const timer = setTimeout(() => process.exit(1), 25000);
        timer.unref();
        server.close(async () => { await mongoose.disconnect(); clearTimeout(timer); process.exit(0); });
    };
    process.once('SIGTERM', shutdown);
    process.once('SIGINT', shutdown);
    return server;
}

if (require.main === module) {
    start().catch(err => {
        console.error('No se pudo iniciar el servidor:', err.name);
        process.exit(1);
    });
}
module.exports = { createApp, User, taskDay, migrateLegacyTasks };
