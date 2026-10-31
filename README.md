# Backend: conexion con la pagina

URL actual: `https://mi-backend-deposito-2.onrender.com`

## Configuracion

Render ejecuta `npm install` y `node server.js`. Configurar variables privadas:

- `MONGO_URI`: cadena de Atlas con la base `apex_global_db`.
- `JWT_SECRET`: secreto aleatorio de al menos 32 bytes. No subirlo a GitHub ni enviarlo al navegador. Cambiarlo invalida sesiones anteriores.
- `TASK_TIMEZONE`: `America/Mexico_City` por defecto. Cada dia comienza a medianoche en esa zona.
- `CORS_ORIGINS`: origenes permitidos separados por comas, por ejemplo `https://ejemplo.com,http://localhost:5173`. Sin rutas ni barra final. Mientras este vacio se permiten todos los origenes; configurarlo al conocer el dominio de la pagina. CORS no sustituye la autenticacion.
- `TRUST_PROXY_HOPS`: `1` en este servicio de Render; `0` en desarrollo directo. No usar `true` ni confiar en todos los proxies. Los limites por correo se aplican incluso si cambia la IP.

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
| `POST /api/forgot-password` | `{ "email": "ana@example.com" }` | 202, mensaje generico sin confirmar si existe la cuenta; 503 si falta configurar correo |
| `POST /api/reset-password` | `{ "token": "token-del-enlace", "password": "nueva-clave-privada" }` | 200, mensaje para volver a iniciar sesion |

`user` contiene `id`, `name`, `email`, `balance`, `vipLevel`, `role`, `taskCompletedToday` y `withdrawRestricted`. Nunca contiene el hash de contrasena.

Las rutas privadas requieren `Authorization: Bearer TOKEN`. El servidor verifica firma HS256, emisor, audiencia y vencimiento, y comprueba que el usuario siga existiendo y no este bloqueado. El rol se lee de la base de datos.

Codigos de error: 400 datos invalidos; 401 sesion ausente/invalida/vencida o credenciales incorrectas; 403 usuario bloqueado; 409 correo duplicado o tarea ya completada; 413 cuerpo demasiado grande; 429 demasiados intentos (respetar `Retry-After`); 500 fallo interno; 503 recuperacion no configurada o salud no disponible.

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

El token dura 24 horas. Al recargar esta pagina de ejemplo se pide iniciar sesion de nuevo. Cerrar sesion borra la copia del navegador; aun no hay revocacion individual en el servidor ni refresh tokens. Restablecer la contrasena invalida todas las sesiones anteriores mediante una version de sesion guardada en MongoDB. Mostrar mensajes como texto, nunca insertar datos del usuario mediante `innerHTML`.

## Limites de intentos

Se guardan contadores atomicos en MongoDB y se eliminan mediante TTL; sobreviven a reinicios y se comparten entre instancias. Ventanas fijas de 15 minutos:

| Operacion | Limite por IP | Limite por correo |
| --- | --- | --- |
| Registro | 10 | No aplica |
| Inicio de sesion | 30 | 10 |
| Solicitar recuperacion | 10 | 3 |
| Restablecer contrasena | 20 | No aplica |

Se cuentan intentos correctos e incorrectos. El limite no bloquea permanentemente la cuenta ni invalida sesiones. Una red compartida puede alcanzar el limite por IP. Los contadores guardan hashes de las IP/correos, no sus valores originales. Se agrupan direcciones IPv6 por /64. Una nueva ventana permite reintentar.

## Activar recuperacion de contrasena

El codigo esta preparado para Resend por HTTPS. No se activa ni envia correos hasta completar en Render:

- `RESEND_API_KEY`: clave privada con permiso de envio del proveedor.
- `EMAIL_FROM`: remitente autorizado de un dominio verificado, por ejemplo `Soporte <soporte@tu-dominio.com>`.
- `PASSWORD_RESET_URL`: direccion HTTPS fija de la pantalla de nueva contrasena del frontend, por ejemplo `https://tu-dominio.com/restablecer-contrasena`. Sin parametros ni fragmentos.

No colocar claves privadas en el frontend, en GitHub ni en capturas. Hay que configurar y verificar el remitente y probar la entrega antes de anunciar esta funcion a usuarios. No se ha creado ninguna cuenta del proveedor ni contratado ningun plan.

El backend encola las solicitudes en MongoDB y responde igual para correos registrados y desconocidos. Un proceso dentro del servidor toma un trabajo cada dos segundos y lo reintenta hasta tres veces si el proveedor falla. La cola expira tras una hora; la entrega puede demorarse cuando el servicio gratuito duerme. Los fallos se registran sin credenciales ni enlaces. Revisar esos errores; no existe aun un panel de entregas fallidas. Una respuesta 202 indica solicitud recibida, no confirmacion de entrega.

El enlace lleva el token en el fragmento `#token=...`, caduca a los 15 minutos y solo el hash se guarda en la cuenta. Una nueva emision invalida el enlace anterior. Cuentas bloqueadas no reciben enlaces. El cambio se aplica solo si el token sigue vigente y sin usar; solicitudes simultaneas solo pueden consumirlo una vez.

La pagina de restablecimiento debe leer y retirar el fragmento inmediatamente, no usar analitica de terceros en esa pantalla y enviar el token en el cuerpo POST:

```javascript
const resetToken = new URLSearchParams(location.hash.slice(1)).get('token');
history.replaceState(null, '', location.pathname);
// Cuando la persona confirme dos veces la nueva contrasena:
await api('/api/reset-password', {
  method: 'POST', body: { token: resetToken, password: nuevaContrasena }
});
cerrarSesion();
// Mostrar confirmacion y llevar a la pantalla de inicio de sesion.
```

No registrar `resetToken`, no guardarlo en almacenamiento persistente y configurar `Referrer-Policy: no-referrer` en esa pantalla. La solicitud inicial usa `api('/api/forgot-password', { method: 'POST', body: { email } })` y debe mostrar el mensaje generico devuelto.

## Tareas diarias

Se conserva la formula existente: `5 + vipLevel * 1.5`. No representa una integracion bancaria o un pago real. El abono y la marca del dia se actualizan juntos en MongoDB; varias solicitudes simultaneas solo pueden producir un abono por usuario y dia. El saldo y el nivel enviados en el cuerpo no controlan el abono.

No hace falta un cron para reiniciar tareas. `/api/me` calcula si la tarea corresponde al dia actual. La marca antigua `taskCompletedToday` se conserva por compatibilidad; usar el valor devuelto por la API. Al arrancar se asigna el dia actual una sola vez a cuentas antiguas que ya estaban marcadas como completadas y no tenian fecha. Estas podran volver a completar al dia siguiente.

## Pruebas

`npm ci` y `npm test`. Se inicia un MongoDB temporal local sin credenciales reales. Cubre registro, validacion, hashes, duplicados, login, tokens falsos y vencidos, bloqueo, suplantacion por `userId`, doce solicitudes simultaneas, cambio de dia, migracion, recuperacion sin revelar cuentas, token vencido/de un uso, cambio de clave, revocacion de sesiones, limites persistentes y reintentos de correo. Los envios se simulan: las pruebas no envian correos. Requiere poder descargar/ejecutar el binario de MongoDB.

## Pendiente antes de usuarios y pagos reales

La ruta anterior `/api/webhook/payment` se conserva sin integrar ni validar una pasarela. NO usar para acreditar dinero real: falta verificar firmas del proveedor, importes, moneda, transacciones e idempotencia. Faltan tambien flujo de retiros, auditoria financiera, activar y verificar la entrega de recuperacion, verificacion inicial del correo, politica completa de sesiones y copias de seguridad. Los archivos antiguos `Transaction.js` y `webhook.js` no son importados por este servidor.

Al terminar el frontend: configurar `CORS_ORIGINS`, conectar formularios y probar mensajes, bloqueo y expiracion de sesiones desde el navegador.
