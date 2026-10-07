let currentToken = "";

// Detectar retorno de OAuth (Google o GitHub) al cargar la página
window.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get('token');
  const email = urlParams.get('email');
  const error = urlParams.get('error');

  if (token && email) {
    currentToken = token;
    // Limpiar los parámetros de la URL de forma limpia
    window.history.replaceState({}, document.title, window.location.pathname);
    mostrarDashboard(decodeURIComponent(email), 'Autenticación Social (OAuth 2.0)');
  } else if (error) {
    window.history.replaceState({}, document.title, window.location.pathname);
    mostrarAlerta("Error al autenticar con el proveedor social", "error");
  }
});

// Cambia la vista visible del panel
function switchPanel(panelId) {
  document.querySelectorAll('.panel').forEach(panel => panel.classList.remove('active'));
  document.getElementById(panelId).classList.add('active');
  ocultarAlerta();
}

// Muestra/Oculta la contraseña (Ojito)
function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  const icon = btn.querySelector('i');
  
  if (input.type === 'password') {
    input.type = 'text';
    icon.classList.remove('fa-eye-slash');
    icon.classList.add('fa-eye');
  } else {
    input.type = 'password';
    icon.classList.remove('fa-eye');
    icon.classList.add('fa-eye-slash');
  }
}

// Alertas del sistema
function mostrarAlerta(msg, type) {
  const box = document.getElementById('alert-box');
  box.className = `alert ${type}`;
  box.textContent = msg;
}

function ocultarAlerta() {
  const box = document.getElementById('alert-box');
  box.className = 'alert';
  box.textContent = '';
}

// 1. REGISTRAR USUARIO
async function registrarUsuario() {
  const nombre = document.getElementById('reg-nombre').value;
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;
  const rol = document.getElementById('reg-rol').value;

  if (!nombre || !email || !password) {
    return mostrarAlerta("Por favor, completa todos los campos", "error");
  }

  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nombre, email, password, rol, tienda: "Arequipa" })
    });

    const data = await res.json();

    if (res.ok) {
      mostrarAlerta("¡Usuario registrado con éxito!", "success");
      document.getElementById('login-email').value = email;
      document.getElementById('login-password').value = password;
      setTimeout(() => switchPanel('login-panel'), 1200);
    } else {
      mostrarAlerta(data.error || "Error al registrar", "error");
    }
  } catch (err) {
    mostrarAlerta("Error de conexión con el servidor", "error");
  }
}

// 2. INICIAR PASO MFA (Obtener QR)
async function iniciarMFA() {
  const email = document.getElementById('login-email').value;

  if (!email) {
    return mostrarAlerta("Ingresa tu correo electrónico", "error");
  }

  try {
    const res = await fetch('/api/auth/mfa/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });

    const data = await res.json();

    if (res.ok && data.qrCodeImage) {
      document.getElementById('qr-image').src = data.qrCodeImage;
      switchPanel('mfa-panel');
    } else {
      mostrarAlerta(data.error || "Debes registrar el usuario primero", "error");
    }
  } catch (err) {
    mostrarAlerta("Error al conectar con el servidor", "error");
  }
}

// 3. VERIFICAR TOTP MFA
async function verificarMFA() {
  const email = document.getElementById('login-email').value;
  const code = document.getElementById('totp-code').value;

  if (!code || code.length !== 6) {
    return mostrarAlerta("Ingresa los 6 dígitos del autenticador", "error");
  }

  try {
    const res = await fetch('/api/auth/mfa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code })
    });

    const data = await res.json();

    if (res.ok && data.token) {
      currentToken = data.token;
      mostrarDashboard(email, "Doble Factor (MFA) Validado");
    } else {
      mostrarAlerta(data.error || "Código TOTP inválido", "error");
    }
  } catch (err) {
    mostrarAlerta("Error al validar código", "error");
  }
}

// 4. INGRESO SOCIAL (Google / GitHub)
function loginSocial(provider) {
  // Redirección directa del navegador requerida por OAuth
  window.location.href = `/api/auth/${provider}`;
}

// 5. MOSTRAR DASHBOARD
function mostrarDashboard(email, metodo) {
  switchPanel('dashboard-panel');
  document.getElementById('user-info').innerHTML = `
    <strong>${email}</strong><br>
    <span style="font-size: 0.8rem; color: #10b981; font-weight: 600;">${metodo}</span>
  `;
  mostrarAlerta("¡Sesión iniciada correctamente!", "success");
}

// 6. CONSULTAR INVENTARIO PROTEGIDO
async function consultarInventario() {
  try {
    const res = await fetch('/api/inventario', {
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });

    const data = await res.json();

    if (res.ok) {
      mostrarAlerta(`✅ [HTTP 200 OK] ${data.mensaje}`, "success");
    } else {
      mostrarAlerta(data.error || "Acceso Denegado (JWT Inválido)", "error");
    }
  } catch (err) {
    mostrarAlerta("Error al consultar el servidor", "error");
  }
}

// 7. CERRAR SESIÓN
function cerrarSesion() {
  currentToken = "";
  document.getElementById('totp-code').value = "";
  switchPanel('login-panel');
  mostrarAlerta("Sesión cerrada correctamente", "success");
}