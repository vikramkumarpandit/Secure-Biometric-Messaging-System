// ==============================================================================
// JAVASCRIPT - SECURE MESSAGING SYSTEM CORE
// ==============================================================================
class SecureMessagingSystem {
    constructor(salt = 0xDEADBEEFCAFEF00Dn) { 
        this._salt = BigInt(salt); 
        this._active_sessions = {}; 
        this._loadState(); 
    }

    _saveState() {
         const stateToSave = { registered_users: {}, used_nonces: {} }; 
         for (const user in this._registered_users) {
             stateToSave.registered_users[user] = this._registered_users[user].toString(); 
            } 
             for (const user in this._used_nonces) {
                 stateToSave.used_nonces[user] = Array.from(this._used_nonces[user]).map(n => n.toString());
                 } 
                 localStorage.setItem('secureSystemState', JSON.stringify(stateToSave)); 
    }
    _loadState() { 
        const savedState = localStorage.getItem('secureSystemState'); 
        if (savedState) { 
            const parsedState = JSON.parse(savedState); 
            this._registered_users = {}; 
            this._used_nonces = {}; 
            for (const user in parsedState.registered_users) { 
                this._registered_users[user] = BigInt(parsedState.registered_users[user]);
            } 
            for (const user in parsedState.used_nonces) { 
                this._used_nonces[user] = new Set(parsedState.used_nonces[user].map(n => BigInt(n)));
            } 
        } 
        else { 
            this._registered_users = {}; 
            this._used_nonces = {}; 
        } 
    }
    clearAllData() {
         this._registered_users = {}; 
         this._used_nonces = {}; 
         this._active_sessions = {}; 
         localStorage.removeItem('secureSystemState'); }
    _mask64(n) {
         return n & 0xFFFFFFFFFFFFFFFFn; 
        }
    _approximate_summer_unit(a, b) { 
        return a ^ b; 
    }
    _approximate_add_v3(a, b) {
         let result = (a & 1n) ^ (b & 1n); 
         for (let i = 0; i < 21; i++) {
             const shift = BigInt(i * 3 + 1); 
             const mask = 0b111n << shift; 
             const a_chunk = (a & mask) >> shift; 
             const b_chunk = (b & mask) >> shift; 
             result |= (this._approximate_summer_unit(a_chunk, b_chunk) << shift); } return this._mask64(result); 
    }
    _derive_key_from_biometrics(vec) {
         if (!Array.isArray(vec) || vec.length !== 3)
            throw new Error("Vector must be an array of 3 numbers."); 
            const packed = (BigInt(vec[0]) << 16n) | (BigInt(vec[1]) << 8n) | BigInt(vec[2]); return this._approximate_add_v3(packed, this._salt); 
    }
    register_user(id, vec) {
         if (this._registered_users[id]) throw new Error(`User '${id}' is already registered.`); 
         const key = this._derive_key_from_biometrics(vec); 
         this._registered_users[id] = key; 
         this._used_nonces[id] = new Set(); this._saveState(); return true; 
    }
    login(id, vec) {
         if (!this._registered_users[id]) 
            throw new Error(`User '${id}' is not registered.`); 
        const key = this._derive_key_from_biometrics(vec); 
        if (key === this._registered_users[id]) {
             this._active_sessions[id] = key; 
             return true; 
        } 
        return false; 
    }
    logout(id) {
         if (this._active_sessions[id]) 
            delete this._active_sessions[id]; 
    }
    create_secure_digest(id, msg) {
         if (!this._active_sessions[id]) 
            throw new Error(`User '${id}' is not logged in.`); 
        const key = this._active_sessions[id];
         const nonce_arr = new BigUint64Array(1); 
         window.crypto.getRandomValues(nonce_arr); const nonce = nonce_arr[0]; 
         const encoder = new TextEncoder();
          let packed_msg = 0n; encoder.encode(msg).forEach((byte, i) => { 
            packed_msg += BigInt(byte) << (BigInt(i % 8) * 8n); 
        }); 
        const temp_hash = this._approximate_add_v3(key, this._mask64(packed_msg)); 
        const digest = this._approximate_add_v3(temp_hash, nonce); return { digest, nonce };
     }

    verify_message(id, msg, digest, nonce) {
         if (!this._registered_users[id]) throw new Error(`Unregistered user '${id}'.`); 
         if (this._used_nonces[id]?.has(nonce)) return 'REPLAY_ATTACK'; const key = this._registered_users[id]; 
         const encoder = new TextEncoder();
          let packed_msg = 0n; encoder.encode(msg).forEach((byte, i) => { 
            packed_msg += BigInt(byte) << (BigInt(i % 8) * 8n); 
        }); 
        const temp_hash = this._approximate_add_v3(key, this._mask64(packed_msg)); 
        const recalc_digest = this._approximate_add_v3(temp_hash, nonce); 
        if (recalc_digest === digest) { 
            this._used_nonces[id].add(nonce); 
            this._saveState(); return 'VALID'; 
        } 
        return 'INVALID_DIGEST'; 
    }
}

// ==============================================================================
// WEB APPLICATION UI LOGIC
// ==============================================================================
document.addEventListener('DOMContentLoaded', () => {
    const system = new SecureMessagingSystem();
    let currentUser = null;
    let messages = JSON.parse(localStorage.getItem('secureMessages')) || [];
    messages.forEach(msg => { msg.digest = BigInt(msg.digest); msg.nonce = BigInt(msg.nonce); });

    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const showLoginBtn = document.getElementById('show-login-btn');
    const showRegisterBtn = document.getElementById('show-register-btn');
    const authContainer = document.getElementById('auth-container');
    const postMessageContainer = document.getElementById('post-message-container');
    const postMessageForm = document.getElementById('post-message-form');
    const logoutBtn = document.getElementById('logout-btn');
    const messageBoard = document.getElementById('message-board');
    const toastEl = document.getElementById('toast');
    const clearDataBtn = document.getElementById('clear-data-btn');
    const themeSwitcher = document.getElementById('theme-switcher');

    // --- SVG Icons ---
    const icons = {
        sun: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386l-1.591 1.591M21 12h-2.25m-.386 6.364l-1.591-1.591M12 18.75V21m-4.773-4.227l-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0z" /></svg>`,
        moon: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25c0 5.385 4.365 9.75 9.75 9.75 2.572 0 4.92-.99 6.697-2.648z" /></svg>`,
        verify: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>`,
        tamper: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487zm0 0L19.5 7.125" /></svg>`,
        reset: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0011.664 0l3.181-3.183m-3.181-4.991v4.99" /></svg>`,
        status: {
            valid: `<svg class="icon-valid" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>`,
            invalid: `<svg class="icon-invalid" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" /></svg>`,
            replay: `<svg class="icon-replay" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" /></svg>`,
            unknown: `<svg class="icon-unknown" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z" /></svg>`
        }
    };

    const showToast = (message, type = 'info') => { toastEl.textContent = message; toastEl.className = `toast show ${type}`; setTimeout(() => { toastEl.className = 'toast'; }, 3000); };
    const parseBioInput = (input) => { const parts = input.split(',').map(s => parseInt(s.trim(), 10)); return (parts.length === 3 && parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) ? parts : null; };
    const saveMessages = () => { const messagesToSave = messages.map(msg => ({ ...msg, digest: msg.digest.toString(), nonce: msg.nonce.toString() })); localStorage.setItem('secureMessages', JSON.stringify(messagesToSave)); };
    
    const renderMessages = () => {
        if (messages.length === 0) { messageBoard.innerHTML = `<p style="text-align: center; padding: 2rem 0; color: var(--text-muted-light);">No messages yet. Register and log in to post one!</p>`; return; }
        messageBoard.innerHTML = messages.map(msg => `
            <div id="msg-${msg.id}" class="message-item ${msg.tampered ? 'tampered' : ''}">
                <div class="message-header">
                    <p class="message-author">${msg.author}</p>
                    <div class="message-status" data-verification-status="unknown" title="Status: Unknown">${icons.status.unknown}</div>
                </div>
                <p class="message-body">${msg.text}</p>
                <div class="message-meta"><p>Digest: 0x${msg.digest.toString(16)}</p><p>Nonce: 0x${msg.nonce.toString(16)}</p></div>
                <div class="message-actions">
                    <button data-action="verify" data-id="${msg.id}" class="btn" title="Verify">${icons.verify} Verify</button>
                    <button data-action="tamper" data-id="${msg.id}" class="btn" title="Tamper">${icons.tamper} Tamper</button>
                    <button data-action="reset" data-id="${msg.id}" class="btn" title="Reset">${icons.reset} Reset</button>
                </div>
            </div>`).join('');
    };
    
    const updateAuthUI = () => { if (currentUser) { authContainer.classList.add('hidden'); postMessageContainer.classList.remove('hidden'); document.getElementById('current-user-name').textContent = currentUser.username; } else { authContainer.classList.remove('hidden'); postMessageContainer.classList.add('hidden'); } };
    
    showLoginBtn.addEventListener('click', () => { loginForm.classList.remove('hidden'); registerForm.classList.add('hidden'); showLoginBtn.classList.add('active'); showRegisterBtn.classList.remove('active'); });
    showRegisterBtn.addEventListener('click', () => { loginForm.classList.add('hidden'); registerForm.classList.remove('hidden'); showRegisterBtn.classList.add('active'); showLoginBtn.classList.remove('active'); });

    registerForm.addEventListener('submit', (e) => { e.preventDefault(); const username = document.getElementById('register-username').value; const bioVector = parseBioInput(document.getElementById('register-bio').value); if (!bioVector) { showToast('Invalid biometric key format.', 'error'); return; } try { system.register_user(username, bioVector); showToast(`User '${username}' registered!`, 'success'); registerForm.reset(); showLoginBtn.click(); } catch (err) { showToast(err.message, 'error'); } });
    loginForm.addEventListener('submit', (e) => { e.preventDefault(); const username = document.getElementById('login-username').value; let bioVector = parseBioInput(document.getElementById('login-bio').value); if (!bioVector) { showToast('Invalid biometric key format.', 'error'); return; } if (document.getElementById('login-noise').checked) { bioVector = bioVector.map(v => (v + Math.floor(Math.random() * 5) - 2 + 256) % 256); showToast('Added random noise to biometric reading.', 'info'); } try { if (system.login(username, bioVector)) { currentUser = { username }; showToast(`Welcome, ${username}!`, 'success'); loginForm.reset(); updateAuthUI(); } else { showToast('Login failed: Biometric data mismatch.', 'error'); } } catch (err) { showToast(err.message, 'error'); } });
    logoutBtn.addEventListener('click', () => { if(currentUser) { system.logout(currentUser.username); showToast(`Logged out.`, 'info'); currentUser = null; updateAuthUI(); } });
    postMessageForm.addEventListener('submit', (e) => { e.preventDefault(); const messageText = document.getElementById('message-text').value; if (!currentUser) { showToast('Must be logged in to post.', 'error'); return; } try { const { digest, nonce } = system.create_secure_digest(currentUser.username, messageText); messages.unshift({ id: Date.now(), author: currentUser.username, text: messageText, originalText: messageText, digest, nonce, tampered: false }); saveMessages(); renderMessages(); postMessageForm.reset(); showToast('Message posted securely!', 'success'); } catch(err) { showToast(err.message, 'error'); } });

    messageBoard.addEventListener('click', (e) => {
        const target = e.target.closest('button');
        if (!target) return;
        const action = target.dataset.action;
        const id = parseInt(target.dataset.id, 10);
        const msg = messages.find(m => m.id === id);
        if (!msg) return;
        const statusElement = document.querySelector(`#msg-${id} .message-status`);
        switch(action) {
            case 'verify': const result = system.verify_message(msg.author, msg.text, msg.digest, msg.nonce); if (result === 'VALID') { statusElement.innerHTML = `<span title="Status: Valid">${icons.status.valid}</span>`; showToast('Message is authentic!', 'success'); } else if (result === 'INVALID_DIGEST') { statusElement.innerHTML = `<span title="Status: Invalid">${icons.status.invalid}</span>`; showToast('Tampering detected!', 'error'); } else if (result === 'REPLAY_ATTACK') { statusElement.innerHTML = `<span title="Status: Replay Attack">${icons.status.replay}</span>`; showToast('Replay attack detected!', 'error'); } break;
            case 'tamper': msg.text += " (tampered!)"; msg.tampered = true; renderMessages(); showToast('Message tampered on client-side.', 'info'); break;
            case 'reset': msg.text = msg.originalText; msg.tampered = false; renderMessages(); showToast('Message reset to original.', 'info'); break;
        }
    });
    
    clearDataBtn.addEventListener('click', () => { if (confirm("Are you sure you want to delete all registered users and messages? This cannot be undone.")) { system.clearAllData(); messages = []; localStorage.removeItem('secureMessages'); renderMessages(); showToast('All application data cleared.', 'success'); } });

    // --- Theme Switcher Logic ---
    const setupTheme = () => {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
            document.body.classList.add('dark-mode');
            themeSwitcher.innerHTML = icons.sun;
        } else {
            document.body.classList.remove('dark-mode');
            themeSwitcher.innerHTML = icons.moon;
        }
    };
    themeSwitcher.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        if (document.body.classList.contains('dark-mode')) {
            localStorage.setItem('theme', 'dark');
            themeSwitcher.innerHTML = icons.sun;
        } else {
            localStorage.setItem('theme', 'light');
            themeSwitcher.innerHTML = icons.moon;
        }
    });

    // --- Initial Load ---
    setupTheme();
    renderMessages();
    updateAuthUI();
});
