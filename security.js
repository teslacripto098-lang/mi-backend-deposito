const { createHash, randomBytes } = require('node:crypto');
const mongoose = require('mongoose');
const { isIP } = require('node:net');

const hash = value => createHash('sha256').update(value).digest('hex');
const Attempt = mongoose.model('SecurityAttempt', new mongoose.Schema({
    _id: String, count: { type: Number, default: 0 }, expiresAt: { type: Date, expires: 0 }
}));
const ResetJob = mongoose.model('PasswordResetJob', new mongoose.Schema({
    email: String, attempts: { type: Number, default: 0 },
    nextAttemptAt: { type: Date, default: Date.now }, lockUntil: { type: Date, default: null },
    expiresAt: { type: Date, expires: 0 }
}));

function clientKey(req) {
    // Render agrega la IP cliente al final de X-Forwarded-For. Express confia solo un salto.
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    if (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(ip)) return ip.slice(7);
    if (isIP(ip) === 6) {
        // Agrupar IPv6 por /64 para no eludir el limite cambiando la parte de host.
        const address = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
        const [left, right = ''] = address.split('::');
        const first = left ? left.split(':') : [];
        const last = right ? right.split(':') : [];
        const words = address.includes('::') ? [...first, ...Array(8-first.length-last.length).fill('0'), ...last] : first;
        if (words.slice(0,5).every(word => parseInt(word,16) === 0) && parseInt(words[5],16) === 65535) {
            const high = parseInt(words[6],16), low = parseInt(words[7],16);
            return [high >> 8, high & 255, low >> 8, low & 255].join('.');
        }
        return words.slice(0,4).map(word => word.padStart(4,'0')).join(':');
    }
    return ip;
}

function limitAttempts(scope, limit, { account = false, clock = () => new Date() } = {}) {
    const windowMs = 15 * 60 * 1000;
    return async (req, res, next) => {
        try {
            const now = clock().getTime();
            const window = Math.floor(now / windowMs);
            const identity = account ? (typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : 'invalid') : clientKey(req);
            const id = `${scope}:${window}:${hash(identity)}`;
            const expiresAt = new Date((window + 1) * windowMs);
            let attempt;
            try {
                attempt = await Attempt.findOneAndUpdate({ _id: id }, {
                    $inc: { count: 1 }, $setOnInsert: { expiresAt }
                }, { upsert: true, new: true });
            } catch (err) {
                if (err.code !== 11000) throw err;
                attempt = await Attempt.findOneAndUpdate({ _id: id }, { $inc: { count: 1 } }, { new: true });
            }
            if (attempt.count > limit) {
                res.set('Retry-After', String(Math.max(1, Math.ceil((expiresAt.getTime()-now)/1000))));
                return res.status(429).json({ error: 'Demasiados intentos. Intenta de nuevo más tarde.' });
            }
            next();
        } catch (err) { next(err); }
    };
}

function recoveryMailer(env = process.env) {
    if (!env.RESEND_API_KEY || !env.EMAIL_FROM || !env.PASSWORD_RESET_URL) return null;
    const page = new URL(env.PASSWORD_RESET_URL);
    if (page.protocol !== 'https:' || page.username || page.password || page.search || page.hash) {
        throw new Error('PASSWORD_RESET_URL debe ser una URL HTTPS fija sin parametros.');
    }
    return async ({ email, token, deliveryId }) => {
        const url = new URL(page);
        // Fragmento: el token no aparece en registros HTTP ni cabeceras Referer.
        url.hash = new URLSearchParams({ token }).toString();
        const response = await fetch('https://api.resend.com/emails', {
            method: 'POST', signal: AbortSignal.timeout(10000),
            headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json', 'Idempotency-Key': deliveryId },
            body: JSON.stringify({ from: env.EMAIL_FROM, to: [email],
                subject: 'Restablecer tu contraseña',
                text: `Recibimos una solicitud para cambiar tu contraseña. Abre este enlace dentro de 15 minutos:\n${url.href}\n\nSi no lo solicitaste, ignora este correo. Nunca compartas el enlace.` })
        });
        if (!response.ok) throw new Error('PasswordEmailDeliveryError');
    };
}

async function processResetJobs({ User, sendReset, clock = () => new Date() }) {
    if (!sendReset) return;
    const now = clock();
    const job = await ResetJob.findOneAndUpdate({
        nextAttemptAt: { $lte: now }, expiresAt: { $gt: now }, attempts: { $lt: 3 },
        $or: [{ lockUntil: null }, { lockUntil: { $lt: now } }]
    }, { $inc: { attempts: 1 }, $set: { lockUntil: new Date(now.getTime()+60000) } }, { new: true, sort: { nextAttemptAt: 1 } });
    if (!job) return;
    let tokenHash, user;
    try {
        user = await User.findOne({ email: job.email }).collation({ locale: 'en', strength: 2 });
        if (user && !user.isBlocked) {
            const token = randomBytes(32).toString('hex');
            tokenHash = hash(token);
            const versionFilter = user.sessionVersion ? { sessionVersion: user.sessionVersion } : {
                $or: [{ sessionVersion: 0 }, { sessionVersion: { $exists: false } }]
            };
            const updated = await User.updateOne({ _id: user._id, isBlocked: false, ...versionFilter }, {
                $set: { resetTokenHash: tokenHash, resetTokenExpiresAt: new Date(now.getTime()+15*60000) }
            });
            if (updated.modifiedCount) await sendReset({ email: user.email, token, deliveryId: `reset-${job._id}-${job.attempts}` });
        }
        await ResetJob.deleteOne({ _id: job._id });
    } catch {
        // Invalidar solo el token de este intento, nunca uno emitido posteriormente.
        if (user && tokenHash) await User.updateOne({ _id: user._id, resetTokenHash: tokenHash }, { $unset: { resetTokenHash: '', resetTokenExpiresAt: '' } });
        await ResetJob.updateOne({ _id: job._id }, { $set: { nextAttemptAt: new Date(now.getTime()+60000), lockUntil: null } });
        console.error('No se pudo entregar un correo de recuperación; se reintentará hasta tres veces.');
    }
}

module.exports = { hash, limitAttempts, recoveryMailer, processResetJobs, Attempt, ResetJob, clientKey };
