const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// ==========================================
// 1. CONFIGURACIÓN DE LA BASE DE DATOS (MongoDB)
// ==========================================
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/apex_global_db';
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('🟢 Conectado exitosamente a MongoDB'))
  .catch(err => console.error('🔴 Error conectando a MongoDB:', err));

// ==========================================
// 2. MODELOS DE DATOS (Esquemas)
// ==========================================
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    vipLevel: { type: Number, default: 1 }, // Soporta del 1 al 3600
    taskCompletedToday: { type: Boolean, default: false },
    isBlocked: { type: Boolean, default: false },
    withdrawRestricted: { type: Boolean, default: false },
    role: { type: String, default: 'client' } // 'client' o 'admin'
});

const User = mongoose.model('User', UserSchema);

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: String, // 'DEPOSIT', 'WITHDRAW', 'TASK'
    amount: Number,
    uniqueWalletCode: String,
    status: { type: String, default: 'PENDING' }, // 'PENDING', 'COMPLETED', 'REJECTED'
    createdAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', TransactionSchema);

// ==========================================
// 3. RUTAS DE AUTENTICACIÓN Y USUARIO
// ==========================================

// Registro de Usuario
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'El correo ya está registrado.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'Usuario registrado con éxito' });
    } catch (err) {
        res.status(500).json({ error: 'Error en el servidor al registrar' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: 'Credenciales inválidas' });

        if (user.isBlocked) return res.status(403).json({ error: 'Tu cuenta ha sido bloqueada por el administrador.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Credenciales inválidas' });

        // Token JWT válido por 24 horas
        const token = jwt.sign({ id: user._id, role: user.role }, 'SECRETO_SUPER_SEGURO', { expiresIn: '24h' });
        
        res.json({ token, role: user.role, user: { name: user.name, balance: user.balance, vipLevel: user.vipLevel } });
    } catch (err) {
        res.status(500).json({ error: 'Error en el login' });
    }
});

// ==========================================
// 4. SISTEMA DE TAREAS DIARIAS (Niveles 1 al 3600)
// ==========================================
app.post('/api/complete-task', async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

        if (user.taskCompletedToday) {
            return res.status(400).json({ error: 'Ya has completado tu tarea de hoy.' });
        }

        // Cálculo dinámico de recompensa basado en el nivel VIP (del 1 al 3600)
        // Ejemplo: Base $5 + un multiplicador progresivo por nivel
        const reward = 5.00 + (user.vipLevel * 1.50);

        user.balance += reward;
        user.taskCompletedToday = true;
        await user.save();

        res.json({ success: true, newBalance: user.balance, reward });
    } catch (err) {
        res.status(500).json({ error: 'Error al procesar la tarea' });
    }
});

// ==========================================
// 5. PASARELA DE PAGOS AUTOMÁTICA (WEBHOOK)
// ==========================================
// Este endpoint lo llama automáticamente tu pasarela de pagos (ej. NowPayments, Cryptomus) cuando el cliente paga
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

// Iniciar servidor en el puerto 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor Backend corriendo en el puerto ${PORT}`);
});
