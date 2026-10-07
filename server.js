const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const passport = require('passport');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'techstore_clave_secreta_jwt_2026_super_segura';

// Middlewares principales
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // Servir archivos estáticos de la carpeta public

// Configuración de Sesiones para Passport
app.use(session({
  secret: 'secreto_de_sesion_techstore',
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());

// Base de datos en memoria
const usuariosDB = [];
const mfaSecrets = {};

// ==========================================
// CONFIGURACIÓN DE PASSPORT (GOOGLE Y GITHUB)
// ==========================================

// Estrategia Google
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID || 'DUMMY_CLIENT_ID',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'DUMMY_CLIENT_SECRET',
    callbackURL: `http://localhost:${PORT}/api/auth/google/callback`
  },
  (accessToken, refreshToken, profile, done) => {
    const user = {
      email: profile.emails && profile.emails[0] ? profile.emails[0].value : `${profile.id}@google.com`,
      nombre: profile.displayName || 'Usuario Google'
    };
    return done(null, user);
  }
));

// Estrategia GitHub
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID || 'DUMMY_CLIENT_ID',
    clientSecret: process.env.GITHUB_CLIENT_SECRET || 'DUMMY_CLIENT_SECRET',
    callbackURL: `http://localhost:${PORT}/api/auth/github/callback`
  },
  (accessToken, refreshToken, profile, done) => {
    const user = {
      email: profile.emails && profile.emails[0] ? profile.emails[0].value : `${profile.username}@github.com`,
      nombre: profile.displayName || profile.username || 'Usuario GitHub'
    };
    return done(null, user);
  }
));

// ==========================================
// RUTAS DE AUTENTICACIÓN LOCAL Y MFA
// ==========================================

// 1. Registro de usuarios
app.post('/api/auth/register', (req, res) => {
  const { nombre, email, password, rol, tienda } = req.body;

  if (!email || !password || !nombre) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  const existe = usuariosDB.find(u => u.email === email);
  if (existe) {
    return res.status(400).json({ error: 'El usuario ya existe' });
  }

  const nuevoUsuario = { nombre, email, password, rol: rol || 'Vendedor', tienda: tienda || 'Arequipa' };
  usuariosDB.push(nuevoUsuario);
  
  return res.json({ mensaje: 'Usuario registrado con éxito' });
});

// 2. Generación de QR para MFA
app.post('/api/auth/mfa/setup', async (req, res) => {
  const { email } = req.body;
  const usuario = usuariosDB.find(u => u.email === email);

  if (!usuario) {
    return res.status(404).json({ error: 'Usuario no registrado. Primero regístrate.' });
  }

  const secret = authenticator.generateSecret();
  mfaSecrets[email] = secret;

  const otpauth = authenticator.keyuri(email, 'TechStore Security', secret);

  try {
    const qrCodeImage = await qrcode.toDataURL(otpauth);
    return res.json({ qrCodeImage });
  } catch (err) {
    return res.status(500).json({ error: 'Error al generar el código QR' });
  }
});

// 3. Verificación del código TOTP de MFA
app.post('/api/auth/mfa/verify', (req, res) => {
  const { email, code } = req.body;
  const secret = mfaSecrets[email];

  if (!secret) {
    return res.status(400).json({ error: 'Primero debes solicitar la clave QR' });
  }

  const isValid = authenticator.check(code, secret);
  if (!isValid) {
    return res.status(401).json({ error: 'Código TOTP incorrecto o expirado' });
  }

  const usuario = usuariosDB.find(u => u.email === email);
  const token = jwt.sign(
    { email: usuario.email, rol: usuario.rol, authMethod: 'MFA Validado (Local)' },
    JWT_SECRET,
    { expiresIn: '2h' }
  );

  return res.json({ mensaje: 'Autenticación exitosa', token, usuario });
});

// ==========================================
// RUTAS OAUTH (GOOGLE Y GITHUB)
// ==========================================

// Ruta Google Iniciar
app.get('/api/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID === 'tu_google_client_id_aqui') {
    // Si no hay llaves reales configuradas, simular ingreso directo para pruebas
    const simEmail = 'demo.google@techstore.com';
    const token = jwt.sign({ email: simEmail, authMethod: 'Google OAuth 2.0 (Modo Prueba)' }, JWT_SECRET, { expiresIn: '2h' });
    return res.redirect(`/?token=${token}&email=${encodeURIComponent(simEmail)}`);
  }
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

// Callback Google
app.get('/api/auth/google/callback', 
  passport.authenticate('google', { session: false, failureRedirect: '/?error=auth_failed' }),
  (req, res) => {
    const token = jwt.sign(
      { email: req.user.email, authMethod: 'Google OAuth 2.0' },
      JWT_SECRET,
      { expiresIn: '2h' }
    );
    res.redirect(`/?token=${token}&email=${encodeURIComponent(req.user.email)}`);
  }
);

// Ruta GitHub Iniciar
app.get('/api/auth/github', (req, res, next) => {
  if (!process.env.GITHUB_CLIENT_ID || process.env.GITHUB_CLIENT_ID === 'tu_github_client_id_aqui') {
    // Si no hay llaves reales configuradas, simular ingreso directo para pruebas
    const simEmail = 'demo.github@techstore.com';
    const token = jwt.sign({ email: simEmail, authMethod: 'GitHub OAuth 2.0 (Modo Prueba)' }, JWT_SECRET, { expiresIn: '2h' });
    return res.redirect(`/?token=${token}&email=${encodeURIComponent(simEmail)}`);
  }
  passport.authenticate('github', { scope: ['user:email'] })(req, res, next);
});

// Callback GitHub
app.get('/api/auth/github/callback', 
  passport.authenticate('github', { session: false, failureRedirect: '/?error=auth_failed' }),
  (req, res) => {
    const token = jwt.sign(
      { email: req.user.email, authMethod: 'GitHub OAuth 2.0' },
      JWT_SECRET,
      { expiresIn: '2h' }
    );
    res.redirect(`/?token=${token}&email=${encodeURIComponent(req.user.email)}`);
  }
);

// ==========================================
// RUTA PROTEGIDA (INVENTARIO CON JWT)
// ==========================================
app.get('/api/inventario', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Acceso Denegado: No se proporcionó Token JWT' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }

    return res.json({
      mensaje: `Acceso concedido a ${decoded.email} [Método: ${decoded.authMethod}]`,
      inventario: [
        { id: 101, producto: 'Laptop Asus ROG Strix', stock: 12, precio: 'S/ 4,500' },
        { id: 102, producto: 'Monitor Dell UltraSharp 27"', stock: 8, precio: 'S/ 1,200' },
        { id: 103, producto: 'Teclado Mecánico Keychron K2', stock: 25, precio: 'S/ 380' }
      ]
    });
  });
});

// Arrancar Servidor
app.listen(PORT, () => {
  console.log(`=================================================`);
  console.log(`🚀 Servidor listo en: http://localhost:${PORT}`);
  console.log(`=================================================`);
});