# Backend: conexion con la pagina

URL actual: `https://mi-backend-deposito-2.onrender.com`

## Configuracion

Render ejecuta `npm install` y `node server.js`. Configurar variables privadas:

- `MONGO_URI`: cadena de Atlas con la base `apex_global_db`.
- `JWT_SECRET`: secreto aleatorio de al menos 32 bytes. No subirlo a GitHub ni enviarlo al navegador. Cambiarlo invalida sesiones anteriores.
- `TASK_TIMEZONE`: `America/Mexico_City` por defecto. Cada dia comienza a medianoche en esa zona.
- `CORS_ORIGINS`: origenes permitidos separados por comas, por ejemplo `https://ejemplo.com,http://localhost:5173`. Sin rutas ni barra final. Mientras este vacio se permiten todos los origenes; configurarlo al conocer el dominio de la pagina. CORS no sustituye la autenticacion.

La base debe estar conectada antes de iniciar el servidor. `GET /health` responde 200 cuando hay conexion y 503 cuando falta.

Para desarrollo, copiar `.env.example` como `.env`, completar valores y ejecutar `node --env-file=.env server.js` en Node 24. No publicar `.env`.

## Contrato de la API

Todas las respuestas son JSON. Los errores tienen forma `{ "error": "mensaje" }`.

| Metodo y ruta | Cuerpo | Respuesta correcta |
| --- | --- | --- |
| `POST /api/register` | `{ "name": "Ana", "email": "ana@example.com", "password": "una-clave-privada" }` | 201, `{ message, user }` |
| `POST /api/login` | `{ "email": "ana@example.com", "password": "una-clave-privada" }` | 200, `{ token, tokenType: "Bearer", expiresIn: 86400, role, user }` |
| `GET /api/me` | Sin cuerpo; requiere token | 200, `{ user }` |
| `POST /api/complete-task` | `{}`; requiere token. No enviar `userId`. | 200, `{ success, newBalance, reward, taskDay, timeZone, user }` |

`user` contiene `id`, `name`, `email`, `balance`, `vipLevel`, `role`, `taskCompletedToday` y `withdrawRestricted`. Nunca contiene el hash de contrasena.

Las rutas privadas requieren `Authorization: Bearer TOKEN`. El servidor verifica firma HS256, emisor, audiencia y vencimiento, y comprueba que el usuario siga existiendo y no este bloqueado. El rol se lee de la base de datos.

Codigos de error: 400 datos invalidos; 401 sesion ausente/invalida/vencida o credenciales incorrectas; 403 usuario bloqueado; 409 correo duplicado o tarea ya completada; 413 cuerpo demasiado grande; 500 fallo interno.

El registro normaliza correos a minusculas y admite contrasenas de 8 caracteres como minimo y 72 bytes como maximo. El login conserva compatibilidad con contrasenas antiguas mas cortas. Las cuentas anteriores se buscan sin distinguir mayusculas.

## Ejemplo para conectar formularios

```javascript
const API = 'https://mi-backend-deposito-2.onrender.com';
let accessToken = null; // Mantener en memoria; no ponerlo en URLs ni logs.

async function api(path, { method = 'GET', body } = {}) {
  const response = await fetch(API + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {})
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const data = await response.json();
  if (response.status === 401) accessToken = null;
  if (!response.ok) throw new Error(data.error || 'No se pudo completar la solicitud');
  return data;
}

async function registrar(name, email, password) {
  return api('/api/register', { method: 'POST', body: { name, email, password } });
}
async function iniciarSesion(email, password) {
  const data = await api('/api/login', { method: 'POST', body: { email, password } });
  accessToken = data.token;
  return data.user;
}
async function consultarMiCuenta() {
  return (await api('/api/me')).user;
}
async function completarTarea() {
  return api('/api/complete-task', { method: 'POST', body: {} });
}
function cerrarSesion() {
  accessToken = null;
}
```

El token dura 24 horas. Al recargar esta pagina de ejemplo se pide iniciar sesion de nuevo. Cerrar sesion borra la copia del navegador; aun no hay revocacion individual en el servidor ni refresh tokens. Mostrar mensajes como texto, nunca insertar datos del usuario mediante `innerHTML`.

## Tareas diarias

Se conserva la formula existente: `5 + vipLevel * 1.5`. No representa una integracion bancaria o un pago real. El abono y la marca del dia se actualizan juntos en MongoDB; varias solicitudes simultaneas solo pueden producir un abono por usuario y dia. El saldo y el nivel enviados en el cuerpo no controlan el abono.

No hace falta un cron para reiniciar tareas. `/api/me` calcula si la tarea corresponde al dia actual. La marca antigua `taskCompletedToday` se conserva por compatibilidad; usar el valor devuelto por la API. Al arrancar se asigna el dia actual una sola vez a cuentas antiguas que ya estaban marcadas como completadas y no tenian fecha. Estas podran volver a completar al dia siguiente.

## Pruebas

`npm ci` y `npm test`. Se inicia un MongoDB temporal local sin credenciales reales. Cubre registro, validacion, hashes, duplicados, login, tokens falsos y vencidos, bloqueo, suplantacion por `userId`, doce solicitudes simultaneas, cambio de dia y migracion de tareas antiguas. Requiere poder descargar/ejecutar el binario de MongoDB.

## Pendiente antes de usuarios y pagos reales

La ruta anterior `/api/webhook/payment` se conserva sin integrar ni validar una pasarela. NO usar para acreditar dinero real: falta verificar firmas del proveedor, importes, moneda, transacciones e idempotencia. Faltan tambien flujo de retiros, auditoria financiera, limites de intentos de autenticacion, recuperacion/verificacion de correo, politica de sesiones y copias de seguridad. Los archivos antiguos `Transaction.js` y `webhook.js` no son importados por este servidor.

Al terminar el frontend: configurar `CORS_ORIGINS`, conectar formularios y probar mensajes, bloqueo y expiracion de sesiones desde el navegador.
