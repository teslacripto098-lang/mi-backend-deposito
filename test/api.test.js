const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { MongoMemoryServer } = require('mongodb-memory-server');
const { createApp, User, taskDay, migrateLegacyTasks } = require('../server');
const { hash, processResetJobs, ResetJob, Attempt, clientKey, recoveryMailer } = require('../security');

const secret = randomBytes(48).toString('hex');
let mongo, server, base, token, userId;
let now = new Date('2026-10-31T18:00:00Z');
const password = 'SoloParaPruebas123';
const deliveries = [];
const sendReset = async message => deliveries.push(message);
async function request(path, { method = 'GET', body, auth } = {}) {
    const response = await fetch(base + path, { method,
        headers: { 'Content-Type': 'application/json', ...(auth ? { Authorization: `Bearer ${auth}` } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, body: await response.json() };
}
before(async () => {
    mongo = await MongoMemoryServer.create({ instance: { args: ['--nounixsocket', '--setParameter', 'diagnosticDataCollectionEnabled=false'] } });
    await mongoose.connect(mongo.getUri());
    await User.init();
    await Promise.all([Attempt.init(), ResetJob.init()]);
    server = createApp({ secret, clock: () => now, sendReset }).listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
    if (server) await new Promise(resolve => server.close(resolve));
    await mongoose.disconnect();
    if (mongo) await mongo.stop();
});

test('configuracion y cambio de dia en Ciudad de Mexico', () => {
    assert.throws(() => createApp({ secret: '' }), /JWT_SECRET/);
    assert.equal(taskDay(new Date('2026-11-01T05:59:59Z'), 'America/Mexico_City'), '2026-10-31');
    assert.equal(taskDay(new Date('2026-11-01T06:00:00Z'), 'America/Mexico_City'), '2026-11-01');
});
test('rechaza entradas invalidas e intentos de inyeccion', async () => {
    for (const body of [{}, { name: 'A', email: { $ne: null }, password },
        { name: 'A', email: 'a@example.com', password: 'short' },
        { name: 'A', email: 'a@example.com', password: 'a'.repeat(73) }]) {
        assert.equal((await request('/api/register', { method: 'POST', body })).status, 400);
    }
    assert.equal((await request('/api/login', { method: 'POST', body: { email: { $ne: null }, password } })).status, 400);
});
test('registro, hash y proteccion contra asignacion de privilegios', async () => {
    const response = await request('/api/register', { method: 'POST', body: {
        name: ' Prueba ', email: ' TEST@EXAMPLE.COM ', password, role: 'admin', balance: 999
    } });
    assert.equal(response.status, 201);
    assert.equal(response.body.user.email, 'test@example.com');
    assert.equal(response.body.user.role, 'client');
    assert.equal(response.body.user.balance, 0);
    assert.equal(response.body.user.password, undefined);
    userId = response.body.user.id;
    const user = await User.findById(userId).select('+password');
    assert.notEqual(user.password, password);
    assert.match(user.password, /^\$2/);
    assert.equal((await request('/api/register', { method: 'POST', body: { name: 'Otra', email: 'TEST@example.com', password } })).status, 409);
});
test('login, credenciales incorrectas y perfil privado', async () => {
    assert.equal((await request('/api/login', { method: 'POST', body: { email: 'test@example.com', password: 'incorrecta' } })).status, 401);
    const login = await request('/api/login', { method: 'POST', body: { email: 'TEST@example.com', password } });
    assert.equal(login.status, 200);
    token = login.body.token;
    assert.equal(login.body.user.password, undefined);
    assert.equal((await request('/api/me')).status, 401);
    assert.equal((await request('/api/me', { auth: 'invalid' })).status, 401);
    const forged = jwt.sign({ sub: userId }, 'SECRETO_SUPER_SEGURO');
    assert.equal((await request('/api/me', { auth: forged })).status, 401);
    const expired = jwt.sign({}, secret, { subject: userId, issuer: 'mi-backend-deposito', audience: 'mi-backend-deposito-web', expiresIn: -1 });
    assert.equal((await request('/api/me', { auth: expired })).status, 401);
    const me = await request('/api/me', { auth: token });
    assert.equal(me.status, 200);
    assert.equal(me.body.user.id, userId);
    assert.equal(me.body.user.password, undefined);
});
test('bloqueo se aplica tambien a sesiones existentes', async () => {
    await User.updateOne({ _id: userId }, { $set: { isBlocked: true } });
    assert.equal((await request('/api/me', { auth: token })).status, 403);
    assert.equal((await request('/api/complete-task', { method: 'POST', auth: token, body: {} })).status, 403);
    assert.equal((await request('/api/login', { method: 'POST', body: { email: 'test@example.com', password } })).status, 403);
    await User.updateOne({ _id: userId }, { $set: { isBlocked: false } });
});
test('tareas: sin sesion, suplantacion y solicitudes simultaneas', async () => {
    assert.equal((await request('/api/complete-task', { method: 'POST', body: {} })).status, 401);
    assert.equal((await request('/api/complete-task', { method: 'POST', auth: token, body: { userId } })).status, 400);
    const responses = await Promise.all(Array.from({ length: 12 }, () => request('/api/complete-task', { method: 'POST', auth: token, body: {} })));
    assert.equal(responses.filter(r => r.status === 200).length, 1);
    assert.equal(responses.filter(r => r.status === 409).length, 11);
    assert.equal((await User.findById(userId)).balance, 6.5);
    assert.equal((await request('/api/me', { auth: token })).body.user.taskCompletedToday, true);
});
test('nuevo dia permite una tarea sin reiniciar el servidor', async () => {
    now = new Date('2026-11-01T06:00:00Z');
    assert.equal((await request('/api/me', { auth: token })).body.user.taskCompletedToday, false);
    const response = await request('/api/complete-task', { method: 'POST', auth: token, body: {} });
    assert.equal(response.status, 200);
    assert.equal(response.body.newBalance, 13);
    assert.equal(response.body.taskDay, '2026-11-01');
});
test('migracion conserva cobros anteriores y es idempotente', async () => {
    const legacy = await User.create({ name: 'Anterior', email: 'legacy@example.com', password: 'hash', taskCompletedToday: true });
    await migrateLegacyTasks('2026-11-01');
    await migrateLegacyTasks('2026-11-02');
    assert.equal((await User.findById(legacy._id)).lastTaskDay, '2026-11-01');
});

test('recuperacion no revela cuentas y guarda solamente hashes', async () => {
    const known = await request('/api/forgot-password', { method: 'POST', body: { email: 'test@example.com' } });
    const unknown = await request('/api/forgot-password', { method: 'POST', body: { email: 'unknown@example.com' } });
    assert.equal(known.status, 202);
    assert.deepEqual(known, unknown);
    assert.equal(deliveries.length, 0);
    await processResetJobs({ User, sendReset, clock: () => now });
    await processResetJobs({ User, sendReset, clock: () => now });
    assert.equal(deliveries.length, 1);
    const stored = await User.findById(userId).select('+resetTokenHash +resetTokenExpiresAt');
    assert.equal(stored.resetTokenHash, hash(deliveries[0].token));
    assert.notEqual(stored.resetTokenHash, deliveries[0].token);
    assert.equal(stored.resetTokenExpiresAt.getTime(), now.getTime()+15*60000);
    assert.equal((await request('/api/me', { auth: token })).body.user.resetTokenHash, undefined);
});
test('restablecer consume el enlace una vez e invalida las sesiones anteriores', async () => {
    const resetToken = deliveries[0].token;
    const newPassword = 'NuevaClaveDePrueba123';
    const responses = await Promise.all(Array.from({ length: 3 }, () => request('/api/reset-password', {
        method: 'POST', body: { token: resetToken, password: newPassword }
    })));
    assert.equal(responses.filter(r => r.status === 200).length, 1);
    assert.equal(responses.filter(r => r.status === 400).length, 2);
    assert.equal((await request('/api/me', { auth: token })).status, 401);
    assert.equal((await request('/api/login', { method: 'POST', body: { email: 'test@example.com', password } })).status, 401);
    const login = await request('/api/login', { method: 'POST', body: { email: 'test@example.com', password: newPassword } });
    assert.equal(login.status, 200);
    assert.equal((await request('/api/me', { auth: login.body.token })).status, 200);
});
test('enlaces vencidos, invalidos y cuentas bloqueadas no cambian contrasenas', async () => {
    const value = 'a'.repeat(64);
    await User.updateOne({ _id: userId }, { $set: { resetTokenHash: hash(value), resetTokenExpiresAt: new Date(now.getTime()-1) } });
    assert.equal((await request('/api/reset-password', { method: 'POST', body: { token: value, password } })).status, 400);
    assert.equal((await request('/api/reset-password', { method: 'POST', body: { token: 'invalid', password } })).status, 400);
    await User.updateOne({ _id: userId }, { $set: { isBlocked: true, resetTokenExpiresAt: new Date(now.getTime()+60000) } });
    assert.equal((await request('/api/reset-password', { method: 'POST', body: { token: value, password } })).status, 400);
    await User.updateOne({ _id: userId }, { $set: { isBlocked: false } });
});
test('limites de acceso sobreviven a nuevas instancias de la aplicacion', async () => {
    const email = 'limite@example.com';
    for (let i=0; i<10; i++) {
        assert.equal((await request('/api/login', { method: 'POST', body: { email, password } })).status, 401);
    }
    assert.equal((await request('/api/login', { method: 'POST', body: { email, password } })).status, 429);
    const other = createApp({ secret, clock: () => now, sendReset }).listen(0, '127.0.0.1');
    await new Promise(resolve => other.once('listening', resolve));
    try {
        const response = await fetch(`http://127.0.0.1:${other.address().port}/api/login`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password })
        });
        assert.equal(response.status, 429);
        assert.ok(Number(response.headers.get('Retry-After')) > 0);
    } finally { await new Promise(resolve => other.close(resolve)); }
});
test('limite de recuperacion y agrupacion IPv6', async () => {
    for (let i=0; i<3; i++) assert.equal((await request('/api/forgot-password', { method: 'POST', body: { email: 'limit-reset@example.com' } })).status,202);
    assert.equal((await request('/api/forgot-password', { method: 'POST', body: { email: 'limit-reset@example.com' } })).status,429);
    assert.equal(clientKey({ ip: '2001:db8:1:2::1' }), clientKey({ ip: '2001:db8:1:2::9' }));
    assert.equal(clientKey({ ip: '::ffff:127.0.0.1' }), '127.0.0.1');
    assert.equal(clientKey({ ip: '::ffff:7f00:1' }), '127.0.0.1');
    assert.equal(recoveryMailer({}), null);
    assert.throws(() => recoveryMailer({ RESEND_API_KEY: 'test', EMAIL_FROM: 'test@example.com', PASSWORD_RESET_URL: 'http://unsafe.test/reset' }), /HTTPS/);
});
test('fallos del proveedor conservan el trabajo y eliminan el token fallido', async () => {
    await ResetJob.deleteMany({});
    await ResetJob.create({ email: 'test@example.com', nextAttemptAt: now, expiresAt: new Date(now.getTime()+3600000) });
    await processResetJobs({ User, sendReset: async () => { throw new Error('Proveedor no disponible'); }, clock: () => now });
    const job = await ResetJob.findOne({ email: 'test@example.com' });
    assert.equal(job.attempts, 1);
    assert.equal(job.nextAttemptAt.getTime(), now.getTime()+60000);
    assert.equal((await User.findById(userId).select('+resetTokenHash')).resetTokenHash, undefined);
});

test('sin proveedor de correo responde 503 sin emitir enlaces', async () => {
    const disabled = createApp({ secret, sendReset: null, clock: () => now }).listen(0, '127.0.0.1');
    await new Promise(resolve => disabled.once('listening',resolve));
    try {
        const response = await fetch(`http://127.0.0.1:${disabled.address().port}/api/forgot-password`, {
            method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({ email: 'disabled@example.com' })
        });
        assert.equal(response.status,503);
        assert.equal(await ResetJob.countDocuments({ email:'disabled@example.com' }),0);
    } finally { await new Promise(resolve => disabled.close(resolve)); }
});
test('adaptador de correo usa HTTPS y fragmento sin enviar mensajes reales', async () => {
    const originalFetch = global.fetch;
    let captured;
    global.fetch = async (url, options) => { captured={ url, options }; return { ok:true }; };
    try {
        const send = recoveryMailer({ RESEND_API_KEY:'test-only-placeholder', EMAIL_FROM:'soporte@example.com', PASSWORD_RESET_URL:'https://example.com/reset' });
        await send({ email:'a@example.com', token:'a'.repeat(64), deliveryId:'test-delivery' });
        assert.equal(captured.url,'https://api.resend.com/emails');
        const body = JSON.parse(captured.options.body);
        assert.match(body.text, /https:\/\/example.com\/reset#token=/);
        assert.deepEqual(body.to,['a@example.com']);
        assert.equal(captured.options.headers['Idempotency-Key'],'test-delivery');
    } finally { global.fetch=originalFetch; }
});
