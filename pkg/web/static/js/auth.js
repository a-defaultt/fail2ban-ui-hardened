// Auth flow for Fail2ban UI.
"use strict";

// =========================================================================
//  Global Variables
// =========================================================================

let authEnabled = false;
let isAuthenticated = false;
let currentUser = null;

// =========================================================================
//  Check Authentication Status
// =========================================================================

async function checkAuthStatus() {
  // Both login page and main content are hidden by default
  // We'll show the appropriate one based on authentication status
  const mainContent = document.getElementById('mainContent');
  const nav = document.querySelector('nav');
  const loginPage = document.getElementById('loginPage');
  const footer = document.getElementById('footer');
  if (loginPage) {
    loginPage.classList.add('hidden');
    loginPage.style.display = 'none';
  }
  if (mainContent) {
    mainContent.classList.add('hidden');
    mainContent.style.display = 'none';
  }
  if (nav) {
    nav.classList.add('hidden');
    nav.style.display = 'none';
  }
  if (footer) {
    footer.classList.add('hidden');
    footer.style.display = 'none';
  }

  try {
    const response = await fetch(appPath('/auth/status'), {
      headers: serverHeaders()
    });

    if (!response.ok) {
      throw new Error('Failed to check auth status');
    }

    const data = await response.json();
    authEnabled = data.enabled || false;
    isAuthenticated = data.authenticated || false;
    const skipLoginPageFlag = data.skipLoginPage || false;

    if (authEnabled) {
      if (isAuthenticated && data.user) {
        // Authenticated: show main content, hide login page
        currentUser = data.user;
        showAuthenticatedUI();
      } else {
        // Not authenticated
        // authMethod is only in the response when authenticated; fall back to body attribute
        const method = data.authMethod || (document.body.getAttribute('data-oidc-enabled') === 'true' ? 'oidc' : 'local');
        if (skipLoginPageFlag && method === 'oidc') {
          window.location.href = appPath('/auth/login');
          return { enabled: authEnabled, authenticated: false, user: null };
        } else {
          showLoginPage(method);
        }
      }
    } else {
      // Auth not enabled: show main content
      showMainContent();
    }

    return { enabled: authEnabled, authenticated: isAuthenticated, user: currentUser };
  } catch (error) {
    console.error('Error checking auth status:', error);
    // [FIX M4] Do NOT silently show a login form when the server is unreachable.
    // Show an explicit error state so the user knows the server is down.
    showServerError(error.message);
    return { enabled: false, authenticated: false, user: null };
  }
}

// =========================================================================
//  Handle Login and Logout
// =========================================================================

// [FIX L1] Accept event explicitly — do not rely on implicit window.event global (non-standard, removed in Firefox).
function handleLogin(event) {
  const loginLoading = document.getElementById('loginLoading');
  const loginError = document.getElementById('loginError');
  const loginErrorText = document.getElementById('loginErrorText');
  const loginButton = event ? event.target.closest('button') : null;

  if (loginLoading) loginLoading.classList.remove('hidden');
  if (loginButton) {
    loginButton.disabled = true;
    loginButton.classList.add('opacity-75', 'cursor-not-allowed');
  }

  if (loginError) {
    loginError.classList.add('hidden');
    if (loginErrorText) loginErrorText.textContent = '';
  }
  window.location.href = appPath('/auth/login?action=redirect');
}

async function handleLocalLogin(event) {
  if (event) event.preventDefault();

  const usernameInput = document.getElementById('usernameInput');
  const passwordInput = document.getElementById('current-password');
  const submitBtn = document.getElementById('localLoginSubmitBtn');
  const btnText = document.getElementById('localLoginBtnText');
  const spin = document.getElementById('localLoginSpin');
  const loginError = document.getElementById('loginError');
  const loginErrorText = document.getElementById('loginErrorText');

  if (!usernameInput || !passwordInput) return;

  const username = usernameInput.value;
  const password = passwordInput.value;

  // Clear previous errors
  if (loginError) loginError.classList.add('hidden');
  if (loginErrorText) loginErrorText.textContent = '';

  // Show loading
  if (submitBtn) submitBtn.disabled = true;
  if (btnText) btnText.classList.add('hidden');
  if (spin) spin.classList.remove('hidden');
  if (usernameInput) usernameInput.disabled = true;
  if (passwordInput) passwordInput.disabled = true;

  try {
    const response = await fetch(appPath('/auth/login'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Invalid credentials or login failed');
    }

    // Success! Refresh status to load dashboard
    const status = await checkAuthStatus();
    
    // Reset loading state if status check completes
    if (submitBtn) submitBtn.disabled = false;
    if (btnText) btnText.classList.remove('hidden');
    if (spin) spin.classList.add('hidden');
    if (usernameInput) {
      usernameInput.disabled = false;
      usernameInput.value = '';
    }
    if (passwordInput) {
      passwordInput.disabled = false;
      passwordInput.value = '';
    }
  } catch (error) {
    console.error('Local login failed:', error);
    if (loginError) loginError.classList.remove('hidden');
    if (loginErrorText) loginErrorText.textContent = error.message;

    // Reset button / inputs
    if (submitBtn) submitBtn.disabled = false;
    if (btnText) btnText.classList.remove('hidden');
    if (spin) spin.classList.add('hidden');
    if (usernameInput) usernameInput.disabled = false;
    if (passwordInput) passwordInput.disabled = false;
  }
}

function togglePasswordVisibility() {
  const passwordInput = document.getElementById('current-password');
  const toggleIcon = document.getElementById('passwordToggleIcon');
  if (!passwordInput || !toggleIcon) return;

  if (passwordInput.type === 'password') {
    passwordInput.type = 'text';
    toggleIcon.classList.remove('fa-eye');
    toggleIcon.classList.add('fa-eye-slash');
  } else {
    passwordInput.type = 'password';
    toggleIcon.classList.remove('fa-eye-slash');
    toggleIcon.classList.add('fa-eye');
  }
}

function handleLogout() {
  // Clear authentication status and redirect to logout endpoint
  isAuthenticated = false;
  currentUser = null;
  window.location.href = appPath('/auth/logout');
}

// =========================================================================
//  Show Different Application States (Login, Main Content, etc.)
// =========================================================================

function showLoginPage(method) {
  const loginPage = document.getElementById('loginPage');
  const mainContent = document.getElementById('mainContent');
  const nav = document.querySelector('nav');
  const footer = document.getElementById('footer');
  
  // Hide main content
  if (mainContent) {
    mainContent.style.display = 'none';
    mainContent.classList.add('hidden');
  }
  if (nav) {
    nav.style.display = 'none';
    nav.classList.add('hidden');
  }
  if (footer) {
    footer.style.display = 'none';
    footer.classList.add('hidden');
  }
  
  // Configure visible containers based on authentication method
  const oidcContainer = document.getElementById('oidcLoginContainer');
  const localContainer = document.getElementById('localLoginContainer');
  const authMethodText = document.getElementById('authMethodText');

  if (oidcContainer) {
    if (method === 'oidc') {
      oidcContainer.classList.remove('hidden');
      if (authMethodText) authMethodText.textContent = 'Secure authentication via OpenID Connect';
    } else {
      oidcContainer.classList.add('hidden');
    }
  }

  if (localContainer) {
    if (method === 'local') {
      localContainer.classList.remove('hidden');
      if (authMethodText) authMethodText.textContent = 'Secure local credentials login';
    } else {
      localContainer.classList.add('hidden');
    }
  }

  // Show login page
  if (loginPage) {
    loginPage.style.display = 'flex';
    loginPage.classList.remove('hidden');
  }
}

// [FIX M4] Show a clear error UI when the server is unreachable instead of silently
// presenting a login form that will never succeed.
function showServerError(message) {
  const loginPage = document.getElementById('loginPage');
  const mainContent = document.getElementById('mainContent');
  const nav = document.querySelector('nav');
  if (mainContent) { mainContent.style.display = 'none'; mainContent.classList.add('hidden'); }
  if (nav) { nav.style.display = 'none'; nav.classList.add('hidden'); }

  // Reuse loginPage as the error container
  const oidcContainer = document.getElementById('oidcLoginContainer');
  const localContainer = document.getElementById('localLoginContainer');
  const loginError = document.getElementById('loginError');
  const loginErrorText = document.getElementById('loginErrorText');
  if (oidcContainer) oidcContainer.classList.add('hidden');
  if (localContainer) localContainer.classList.add('hidden');
  if (loginError) loginError.classList.remove('hidden');
  if (loginErrorText) loginErrorText.textContent = 'Cannot reach server: ' + (message || 'unknown error') + '. Please refresh or check your connection.';
  if (loginPage) { loginPage.style.display = 'flex'; loginPage.classList.remove('hidden'); }
}

function showMainContent() {
  const loginPage = document.getElementById('loginPage');
  const mainContent = document.getElementById('mainContent');
  const nav = document.querySelector('nav');
  const footer = document.getElementById('footer');
  
  // Hide login page
  if (loginPage) {
    loginPage.style.display = 'none';
    loginPage.classList.add('hidden');
  }
  
  // Show main content
  if (mainContent) {
    mainContent.style.display = 'block';
    mainContent.classList.remove('hidden');
  }
  if (nav) {
    nav.style.display = 'block';
    nav.classList.remove('hidden');
  }
  if (footer) {
    footer.style.display = 'block';
    footer.classList.remove('hidden');
  }
}

function showAuthenticatedUI() {
  showMainContent();

  const userInfoContainer = document.getElementById('userInfoContainer');
  const userDisplayName = document.getElementById('userDisplayName');
  const userMenuDisplayName = document.getElementById('userMenuDisplayName');
  const userMenuEmail = document.getElementById('userMenuEmail');
  const mobileUserInfoContainer = document.getElementById('mobileUserInfoContainer');
  const mobileUserDisplayName = document.getElementById('mobileUserDisplayName');
  const mobileUserEmail = document.getElementById('mobileUserEmail');

  if (userInfoContainer && currentUser) {
    userInfoContainer.classList.remove('hidden');

    const displayName = currentUser.name || currentUser.username || currentUser.email;

    if (userDisplayName) {
      userDisplayName.textContent = displayName;
    }

    if (userMenuDisplayName) {
      userMenuDisplayName.textContent = displayName;
    }

    if (userMenuEmail && currentUser.email) {
      userMenuEmail.textContent = currentUser.email;
    }
  }
  
  // Update mobile menu
  if (mobileUserInfoContainer && currentUser) {
    mobileUserInfoContainer.classList.remove('hidden');

    const displayName = currentUser.name || currentUser.username || currentUser.email;

    if (mobileUserDisplayName) {
      mobileUserDisplayName.textContent = displayName;
    }

    if (mobileUserEmail && currentUser.email) {
      mobileUserEmail.textContent = currentUser.email;
    }
  }
}

// =========================================================================
//  Helper Functions
// =========================================================================

function toggleUserMenu() {
  const dropdown = document.getElementById('userMenuDropdown');
  if (dropdown) {
    dropdown.classList.toggle('hidden');
  }
}

document.addEventListener('click', function(event) {
  const userMenuButton = document.getElementById('userMenuButton');
  const userMenuDropdown = document.getElementById('userMenuDropdown');

  if (userMenuButton && userMenuDropdown &&
      !userMenuButton.contains(event.target) &&
      !userMenuDropdown.contains(event.target)) {
    userMenuDropdown.classList.add('hidden');
  }
});
