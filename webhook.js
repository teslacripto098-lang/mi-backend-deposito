// Ruta para recibir la notificación automática (Webhook) de la pasarela de pagos
app.post('/api/webhook/payment', async (req, res) => {
    try {
        // Dependiendo de la pasarela, los datos llegan en req.body (por ejemplo: order_id y status)
        const { order_id, status } = req.body;

        // 1. Buscamos la transacción pendiente usando el código único que generamos antes
        const transaction = await Transaction.findOne({ uniqueWalletCode: order_id });

        if (!transaction) {
            return res.status(404).json({ error: 'Transacción no encontrada' });
        }

        // 2. Verificamos si el pago se completó con éxito
        if (status === 'success' || status === 'completed') {
            transaction.status = 'COMPLETED';
            await transaction.save();

            // AQUÍ PUEDES AGREGAR LA LÓGICA PARA SUMARLE EL SALDO AL USUARIO:
            // Por ejemplo: await User.findByIdAndUpdate(transaction.userId, { $inc: { balance: transaction.amount } });

            console.log(`¡Pago acreditado con éxito para la orden: ${order_id}!`);
        }

        // Respondemos a la pasarela para que sepa que recibimos el aviso correctamente
        res.json({ received: true });
    } catch (err) {
        console.error('Error en el webhook:', err);
        res.status(500).json({ error: 'Error procesando el webhook' });
    }
});