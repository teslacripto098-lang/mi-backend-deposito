const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { MongoMemoryServer } = require('mongodb-memory-server');
const { createApp, User, taskDay, migrateLegacyTasks } = require('../server');

const secret = randomBytes(48).toString('hex');
let mongo, server, base, token, userId;
let now = new Date('2026-10-31T18:00:00Z');
const password = 'SoloParaPruebas123';
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
    server = createApp({ secret, clock: () => now }).listen(0, '127.0.0.1');
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
