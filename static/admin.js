    let allLogs = [];
    let allUsers = [];
    let filteredLogs = [];
    let isAuthenticated = false;
    let csrfToken = '';

    // ====== AUTH ======
    async function login() {
        const password = document.getElementById('adminPassword').value;
        const rememberMe = document.getElementById('rememberMe').checked;
        const errorDiv = document.getElementById('loginError');
        errorDiv.style.display = 'none';
        try {
            const res = await fetch('/admin/auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                cache: 'no-store',
                body: JSON.stringify({ password, remember_me: rememberMe })
            });
            const data = await res.json();
            if (data.status === 'success') {
                // The password was accepted, but the login lives in a session cookie. If the browser
                // refuses to keep it (typically a Secure cookie on a plain-HTTP page) a reload would
                // just show this form again with no explanation, so confirm the session first.
                let sessionKept = true;
                try {
                    const check = await fetch('/admin/check-auth', {
                        credentials: 'same-origin',
                        cache: 'no-store'
                    });
                    sessionKept = !!(await check.json()).authenticated;
                } catch (e) {
                    sessionKept = true; // cannot tell: fall back to the normal reload
                }
                if (sessionKept) {
                    window.location.reload();
                } else {
                    const local = ['localhost', '127.0.0.1', '[::1]'].includes(window.location.hostname);
                    errorDiv.textContent = (window.location.protocol === 'http:' && !local)
                        ? 'Password accepted, but your browser did not keep the login session. This page is '
                          + 'loaded over plain HTTP and the session cookie is marked Secure, which browsers refuse '
                          + 'to store over HTTP. Open DoorOpener over HTTPS (for example behind a reverse proxy), '
                          + 'or on a trusted network set SESSION_COOKIE_SECURE=false and restart the container.'
                        : 'Password accepted, but your browser did not keep the login session. Check that cookies '
                          + 'are enabled for this site and that your reverse proxy forwards X-Forwarded-Proto.';
                    errorDiv.style.display = 'block';
                }
            } else {
                errorDiv.textContent = 'Invalid admin password';
                errorDiv.style.display = 'block';
            }
        } catch (error) {
            errorDiv.textContent = 'Error connecting to server';
            errorDiv.style.display = 'block';
        }
    }

    async function showDashboard() {
        isAuthenticated = true;
        document.getElementById('loginForm').style.display = 'none';
        document.getElementById('dashboard').style.display = 'block';
        await Promise.all([loadLogs(), loadUsers(), loadNotice(), loadTestMode()]);
    }

    async function loadNotice() {
        try {
            const res = await fetch('/admin/notice', { credentials: 'same-origin', cache: 'no-store' });
            const data = await res.json();
            const text = data.notice || '';
            document.getElementById('noticeText').value = text;
            updateNoticePreview(text);
        } catch (_) {}
    }

    async function loadTestMode() {
        try {
            const res = await fetch('/admin/test-mode', { credentials: 'same-origin', cache: 'no-store' });
            const data = await res.json();
            setTestModeUI(data.test_mode);
        } catch (_) {}
    }

    function setTestModeUI(enabled) {
        document.getElementById('testModeToggle').checked = enabled;
        document.getElementById('testModeLabel').textContent = enabled ? 'ON — door will not open' : 'Off';
        document.getElementById('testModeLabel').style.color = enabled ? '#ffb300' : '';
        document.getElementById('testModeWarning').style.display = enabled ? 'block' : 'none';
    }

    function updateNoticePreview(text) {
        const el = document.getElementById('noticePreview');
        if (text.trim()) {
            el.textContent = text.trim();
            el.classList.add('active');
        } else {
            el.textContent = '';
            el.classList.remove('active');
        }
    }

    if (document.getElementById('dashboard')) {

    document.getElementById('testModeToggle').addEventListener('change', async function() {
        const enabled = this.checked;
        const statusEl = document.getElementById('testModeStatus');
        try {
            const res = await fetch('/admin/test-mode', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                body: JSON.stringify({ enabled })
            });
            const data = await res.json();
            if (res.ok) {
                setTestModeUI(data.test_mode);
                statusEl.textContent = data.test_mode ? 'Test mode enabled.' : 'Test mode disabled.';
                statusEl.classList.add('visible');
                setTimeout(() => statusEl.classList.remove('visible'), 2500);
            } else {
                statusEl.textContent = data.error || 'Error saving.';
                statusEl.classList.add('visible');
                this.checked = !enabled; // revert
            }
        } catch (_) {
            statusEl.textContent = 'Network error.';
            statusEl.classList.add('visible');
            this.checked = !enabled; // revert
        }
    });

    document.getElementById('noticeText').addEventListener('input', function() {
        updateNoticePreview(this.value);
    });

    document.getElementById('btnSaveNotice').addEventListener('click', async function() {
        const text = document.getElementById('noticeText').value.trim();
        const statusEl = document.getElementById('noticeStatus');
        try {
            const res = await fetch('/admin/notice', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                body: JSON.stringify({ notice: text })
            });
            const data = await res.json();
            if (res.ok) {
                statusEl.textContent = text ? 'Notice saved.' : 'Notice cleared.';
                statusEl.classList.add('visible');
                setTimeout(() => statusEl.classList.remove('visible'), 2500);
                updateNoticePreview(data.notice || '');
            } else {
                statusEl.textContent = data.error || 'Error saving.';
                statusEl.classList.add('visible');
            }
        } catch (_) {
            statusEl.textContent = 'Network error.';
            statusEl.classList.add('visible');
        }
    });

    document.getElementById('btnClearNotice').addEventListener('click', async function() {
        document.getElementById('noticeText').value = '';
        document.getElementById('btnSaveNotice').click();
    });

    // --- Background image ---
    const bgFileInput = document.getElementById('bgFileInput');
    const btnUploadBg = document.getElementById('btnUploadBg');
    const btnResetBg = document.getElementById('btnResetBg');
    const bgPreviewImg = document.getElementById('bgPreviewImg');
    const bgStatus = document.getElementById('bgStatus');

    function showBgStatus(msg, isError) {
        bgStatus.textContent = msg;
        bgStatus.classList.toggle('error', !!isError);
        bgStatus.classList.add('visible');
        if (!isError) setTimeout(() => bgStatus.classList.remove('visible'), 2500);
    }

    bgFileInput.addEventListener('change', function() {
        const file = this.files[0];
        if (!file) { btnUploadBg.disabled = true; return; }
        btnUploadBg.disabled = false;
        const reader = new FileReader();
        reader.onload = e => { bgPreviewImg.src = e.target.result; };
        reader.readAsDataURL(file);
    });

    btnUploadBg.addEventListener('click', async function() {
        const file = bgFileInput.files[0];
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        btnUploadBg.disabled = true;
        try {
            const res = await fetch('/admin/background', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'X-CSRF-Token': csrfToken },
                body: formData
            });
            const data = await res.json();
            if (res.ok) {
                showBgStatus('Background updated.');
                bgFileInput.value = '';
            } else {
                showBgStatus(data.error || 'Upload failed.', true);
                btnUploadBg.disabled = false;
            }
        } catch (_) {
            showBgStatus('Network error.', true);
            btnUploadBg.disabled = false;
        }
    });

    btnResetBg.addEventListener('click', async function() {
        if (!(await confirmDialog('Reset background', 'Reset background to the original default image?'))) return;
        try {
            const res = await fetch('/admin/background', {
                method: 'DELETE',
                credentials: 'same-origin',
                headers: { 'X-CSRF-Token': csrfToken }
            });
            const data = await res.json();
            if (res.ok) {
                bgPreviewImg.src = '/static/background.jpg?t=' + Date.now();
                showBgStatus('Reset to default.');
            } else {
                showBgStatus(data.error || 'Reset failed.', true);
            }
        } catch (_) {
            showBgStatus('Network error.', true);
        }
    });

    } // end dashboard guard

    function showLogin() {
        document.getElementById('loginForm').style.display = 'block';
        const dash = document.getElementById('dashboard');
        if (dash) dash.style.display = 'none';
    }

    async function checkAuthentication() {
        try {
            const res = await fetch('/admin/check-auth', { credentials: 'same-origin', cache: 'no-store' });
            const data = await res.json();
            if (data.authenticated) {
                if (data.csrf_token) csrfToken = data.csrf_token;
                await showDashboard();
            } else {
                showLogin();
            }
        } catch (e) {
            showLogin();
        }
    }

    function logout() {
        fetch('/admin/logout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            credentials: 'same-origin',
            cache: 'no-store'
        }).finally(() => {
            isAuthenticated = false;
            showLogin();
            document.getElementById('adminPassword').value = '';
            document.getElementById('rememberMe').checked = false;
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        checkAuthentication();

        // Auth — login form is always present
        document.getElementById('loginBtn').addEventListener('click', login);
        document.getElementById('adminPassword').addEventListener('keypress', e => { if (e.key === 'Enter') login(); });

        // Dashboard elements are only rendered when authenticated
        if (document.getElementById('dashboard')) {
            document.getElementById('logoutBtn').addEventListener('click', logout);

            // Tabs
            document.getElementById('tabLogsBtn').addEventListener('click', () => switchTab('logs'));
            document.getElementById('tabUsersBtn').addEventListener('click', () => switchTab('users'));
            document.getElementById('tabActivityBtn').addEventListener('click', () => switchTab('activity'));

            // Log controls
            document.getElementById('sortBy').addEventListener('change', sortLogs);
            document.getElementById('filterUser').addEventListener('change', filterLogs);
            document.querySelectorAll('#logCategories .chip').forEach(chip => {
                chip.addEventListener('click', () => {
                    logCategory = chip.dataset.cat;
                    updateCategoryChips();
                    filterLogs();
                });
            });
            document.getElementById('btnRefreshLogs').addEventListener('click', loadLogs);
            document.getElementById('btnClearAll').addEventListener('click', () => openClearAll('btnClearAll'));

            // User controls
            document.getElementById('btnMigrateAll').addEventListener('click', () => openMigrateAll('btnMigrateAll'));
            document.getElementById('btnAddUser').addEventListener('click', openAddUser);

            // Event delegation for dynamically rendered user action buttons
            document.getElementById('dashboard').addEventListener('click', e => {
                const btn = e.target.closest('[data-action]');
                if (!btn) return;
                const action = btn.dataset.action;
                const username = btn.dataset.username;
                if (action === 'edit') openEditUser(username);
                else if (action === 'toggle') toggleActive(username, btn.dataset.active === 'true');
                else if (action === 'delete') deleteUser(username);
            });
        }

        checkForUpdate(DOOR_CONFIG.appVersion);
    });

    // ====== LOGS ======
    let _loading = false;
    async function loadLogs() {
        if (!isAuthenticated || _loading) return;
        _loading = true;
        try {
            const res = await fetch('/admin/logs', { credentials: 'same-origin', cache: 'no-store' });
            const data = await res.json();
            allLogs = data.logs || [];
            populateUserFilter();
            updateCategoryChips();
            filterLogs();
            updateStats();
            loadStats();
        } catch (e) {
            document.getElementById('logTableBody').innerHTML = '<tr><td colspan="5" class="no-data">Error loading logs</td></tr>';
        } finally {
            _loading = false;
        }
    }

    // ====== STATS + LEADERBOARD ======
    let _statsLoading = false;
    let _statsAgain = false;
    async function loadStats() {
        if (!isAuthenticated) return;
        if (_statsLoading) { _statsAgain = true; return; }  // re-run afterwards so a refresh is never dropped
        _statsLoading = true;
        try {
            const res = await fetch('/admin/stats', { credentials: 'same-origin', cache: 'no-store' });
            if (!res.ok) throw new Error('stats ' + res.status);
            AdminStats.render(await res.json());
        } catch (e) {
            const note = document.getElementById('statsNote');
            if (note) note.textContent = 'Could not load statistics.';
        } finally {
            _statsLoading = false;
            if (_statsAgain) { _statsAgain = false; loadStats(); }
        }
    }

    function updateStats() {
        updateLeaderboard();
    }

    function updateLeaderboard() {
        // Build from user store times_used — consistent with the Users table
        const active = allUsers.filter(u => (u.times_used || 0) > 0);
        const sorted = [...active].sort((a, b) => (b.times_used || 0) - (a.times_used || 0)).slice(0, 8);
        const maxCount = sorted.length ? sorted[0].times_used : 1;

        const lbSection = document.getElementById('leaderboardSection');
        const lbRows = document.getElementById('leaderboardRows');
        if (sorted.length) {
            lbSection.style.display = 'block';
            lbRows.innerHTML = '';
            sorted.forEach((u, i) => {
                const rankCls = i === 0 ? 'rank-1' : i === 1 ? 'rank-2' : i === 2 ? 'rank-3' : 'rank-n';
                const cnt = u.times_used || 0;
                const pct = Math.round(cnt / maxCount * 100);
                const row = document.createElement('div');
                row.className = 'lb-row';
                row.innerHTML = `<div class="rank ${rankCls}">${i + 1}</div>
                    <div class="lb-name">${escapeHtml(u.username)}</div>
                    <div class="lb-bar-wrap"><div class="lb-bar"></div></div>
                    <div class="lb-count">${cnt}</div>`;
                row.querySelector('.lb-bar').style.width = pct + '%';
                lbRows.appendChild(row);
            });
        } else {
            lbSection.style.display = 'none';
        }
    }

    // ====== USERS ======
    async function loadUsers() {
        try {
            const res = await fetch('/admin/users', { credentials: 'same-origin', cache: 'no-store' });
            const data = await res.json();
            allUsers = data.users || [];
            renderUsers(allUsers);
            updateLeaderboard();
        } catch (e) {
            const tbody = document.getElementById('usersTableBody');
            if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="no-data">Error loading users</td></tr>';
        }
    }

    function timeAgo(isoString) {
        if (!isoString) return '—';
        const diff = Date.now() - new Date(isoString).getTime();
        const s = Math.floor(diff / 1000);
        if (s < 60) return 'just now';
        const m = Math.floor(s / 60);
        if (m < 60) return m + 'm ago';
        const h = Math.floor(m / 60);
        if (h < 24) return h + 'h ago';
        const d = Math.floor(h / 24);
        if (d < 30) return d + 'd ago';
        const mo = Math.floor(d / 30);
        if (mo < 12) return mo + 'mo ago';
        return Math.floor(mo / 12) + 'y ago';
    }

    function renderUsers(users) {
        const tbody = document.getElementById('usersTableBody');
        const cards = document.getElementById('userCards');
        if (!tbody) return;
        if (!users.length) {
            tbody.innerHTML = '<tr><td colspan="7" class="no-data">No users found</td></tr>';
            if (cards) cards.innerHTML = '';
            return;
        }

        const configUsers = users.filter(u => u.source === 'config');
        const migrateBtn = document.getElementById('btnMigrateAll');
        if (migrateBtn) migrateBtn.style.display = configUsers.length > 0 ? 'inline-flex' : 'none';

        tbody.innerHTML = users.map(u => {
            const activeBadge = u.active
                ? '<span class="badge badge-active">Active</span>'
                : '<span class="badge badge-inactive">Inactive</span>';
            const srcBadge = u.source === 'config'
                ? '<span class="badge badge-config">Config</span>'
                : '<span class="badge badge-store">Store</span>';
            const created  = u.created_at   ? `<span title="${new Date(u.created_at).toLocaleString()}">${timeAgo(u.created_at)}</span>`   : '—';
            const lastUsed = u.last_used_at ? `<span title="${new Date(u.last_used_at).toLocaleString()}">${timeAgo(u.last_used_at)}</span>` : '—';
            const uses = u.times_used || 0;

            let actions = '';
            if (u.can_edit) {
                actions = `
                    <button class="btn btn-purple btn-sm" data-action="edit" data-username="${escapeHtml(u.username)}">Edit</button>
                    <button class="btn ${u.active ? 'btn-teal' : 'btn-success'} btn-sm"
                            data-action="toggle" data-username="${escapeHtml(u.username)}" data-active="${!u.active}">
                        ${u.active ? 'Deactivate' : 'Activate'}
                    </button>
                    <button class="btn btn-danger btn-sm" data-action="delete" data-username="${escapeHtml(u.username)}">Delete</button>
                `;
            } else {
                actions = '<span class="cfg-only">Config-only</span>';
            }
            return `<tr>
                <td class="td-user">${escapeHtml(u.username)}</td>
                <td>${activeBadge}</td>
                <td>${srcBadge}</td>
                <td class="td-date">${created}</td>
                <td class="td-date">${lastUsed}</td>
                <td class="td-uses">${uses}</td>
                <td><div class="td-acts">${actions}</div></td>
            </tr>`;
        }).join('');

        if (cards) {
            cards.innerHTML = users.map(u => {
                const lastUsed = u.last_used_at ? `<span title="${new Date(u.last_used_at).toLocaleString()}">${timeAgo(u.last_used_at)}</span>` : '—';
                const actions = u.can_edit ? `
                    <div class="mc-actions">
                        <button class="btn btn-purple btn-sm" data-action="edit" data-username="${escapeHtml(u.username)}">Edit</button>
                        <button class="btn ${u.active ? 'btn-teal' : 'btn-success'} btn-sm"
                                data-action="toggle" data-username="${escapeHtml(u.username)}" data-active="${!u.active}">
                            ${u.active ? 'Deactivate' : 'Activate'}
                        </button>
                        <button class="btn btn-danger btn-sm" data-action="delete" data-username="${escapeHtml(u.username)}">Delete</button>
                    </div>` : '';
                return `<div class="glass mobile-card">
                    <div class="mobile-card-hd">
                        <strong class="mc-name">${escapeHtml(u.username)}</strong>
                        ${u.active ? '<span class="badge badge-active">Active</span>' : '<span class="badge badge-inactive">Inactive</span>'}
                    </div>
                    <div class="mobile-card-body">
                        <div class="mrow"><span class="mlabel">Source</span><span class="mvalue">${escapeHtml(u.source||'store')}</span></div>
                        <div class="mrow"><span class="mlabel">Uses</span><span class="mvalue mc-uses">${u.times_used||0}</span></div>
                        <div class="mrow"><span class="mlabel">Last Used</span><span class="mvalue mc-small">${lastUsed}</span></div>
                    </div>
                    ${actions}
                </div>`;
            }).join('');
        }
    }

    // ====== LOG FILTER / SORT / RENDER ======
    function populateUserFilter() {
        const sel = document.getElementById('filterUser');
        const users = [...new Set(allLogs.map(l => l.user).filter(Boolean))].sort();
        sel.innerHTML = '<option value="">All</option>' +
            users.map(u => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`).join('');
    }

    // ====== LOG CATEGORIES ======
    let logCategory = 'door';  // door | security | admin | system | '' (all)
    const CATEGORY_HINTS = {
        door: 'Keypad and SSO attempts: who opened the door, wrong PINs, disabled accounts.',
        security: 'The rate limiter stepping in: blocked sessions and IP addresses.',
        admin: 'Everything done in this dashboard: logins, user changes, clearing logs.',
        system: 'Faults: the PIN was right but the door did not open (Home Assistant or server errors).',
        '': 'Everything, all categories.',
    };

    function updateCategoryChips() {
        const counts = { '': allLogs.length };
        allLogs.forEach(l => { counts[l.category] = (counts[l.category] || 0) + 1; });
        document.querySelectorAll('#logCategories .chip').forEach(chip => {
            const cat = chip.dataset.cat;
            chip.querySelector('.chip-n').textContent = counts[cat] || 0;
            const on = cat === logCategory;
            chip.classList.toggle('active', on);
            chip.setAttribute('aria-pressed', String(on));
        });
        const hint = document.getElementById('logCategoryHint');
        if (hint) hint.textContent = CATEGORY_HINTS[logCategory] || '';
    }

    function logBadge(log) {
        const cls = { ok: 'badge-success', bad: 'badge-failure', warn: 'badge-warn', info: 'badge-info' }[log.severity] || 'badge-info';
        const icon = logCategory ? '' : ((AdminStats.CATEGORY_ICON[log.category] || '') + ' ');
        return `<span class="badge ${cls}">${icon}${escapeHtml(log.label || log.status || 'Unknown')}</span>`
            + (log.test ? ' <span class="badge badge-test">test</span>' : '');
    }

    function filterLogs() {
        const uf = document.getElementById('filterUser').value;
        filteredLogs = allLogs.filter(l =>
            (!logCategory || l.category === logCategory) && (!uf || l.user === uf)
        );
        sortLogs();
    }

    function sortLogs() {
        const s = document.getElementById('sortBy').value;
        filteredLogs.sort((a, b) => {
            if (s === 'time')     return b.timestamp.localeCompare(a.timestamp);
            if (s === 'time_asc') return a.timestamp.localeCompare(b.timestamp);
            if (s === 'user')     return (a.user||'').localeCompare(b.user||'');
            if (s === 'status')   return (a.label || a.status || '').localeCompare(b.label || b.status || '');
            return 0;
        });
        renderLogs();
    }

    function renderLogs() {
        const tbody   = document.getElementById('logTableBody');
        const cardEl  = document.getElementById('logCards');

        if (!filteredLogs.length) {
            const none = logCategory ? 'No ' + logCategory + ' events logged' : 'No logs found';
            tbody.innerHTML = '<tr><td colspan="5" class="no-data">' + none + '</td></tr>';
            if (cardEl) cardEl.innerHTML = '';
            return;
        }

        tbody.innerHTML = filteredLogs.map(log => {
            const ts = fmtTs(log.timestamp);
            const badge = logBadge(log);
            return `<tr>
                <td class="td-ts">${ts}</td>
                <td class="td-ip">${escapeHtml(log.ip||'')}</td>
                <td class="td-user">${escapeHtml(log.user||'Unknown')}</td>
                <td>${badge}</td>
                <td class="td-det">${escapeHtml(log.details||'—')}</td>
            </tr>`;
        }).join('');

        if (cardEl) {
            cardEl.innerHTML = filteredLogs.map(log => {
                const ts = fmtTs(log.timestamp);
                const badge = logBadge(log);
                return `<div class="glass mobile-card">
                    <div class="mobile-card-hd">
                        <strong class="mc-name">${escapeHtml(log.user||'Unknown')}</strong>
                        ${badge}
                    </div>
                    <div class="mobile-card-body">
                        <div class="mrow"><span class="mlabel">Time</span><span class="mvalue mc-tinyts">${ts}</span></div>
                        <div class="mrow"><span class="mlabel">IP</span><span class="mvalue mc-mono">${escapeHtml(log.ip||'')}</span></div>
                        <div class="mrow"><span class="mlabel">Details</span><span class="mvalue">${escapeHtml(log.details||'—')}</span></div>
                    </div>
                </div>`;
            }).join('');
        }
    }

    function fmtTs(ts) {
        try { const d = new Date(ts); if (!isNaN(d)) return d.toLocaleString(); } catch(e) {}
        return ts;
    }

    // ====== TABS ======
    function switchTab(tab) {
        document.getElementById('tabLogsBtn').classList.toggle('active', tab === 'logs');
        document.getElementById('tabUsersBtn').classList.toggle('active', tab === 'users');
        document.getElementById('tabActivityBtn').classList.toggle('active', tab === 'activity');
        document.getElementById('logsTab').style.display      = tab === 'logs'     ? 'block' : 'none';
        document.getElementById('usersTab').style.display     = tab === 'users'    ? 'block' : 'none';
        document.getElementById('activityTab').style.display  = tab === 'activity' ? 'block' : 'none';
        if (tab === 'logs') loadLogs();
        else if (tab === 'users') loadUsers();
        else if (tab === 'activity') loadStats();
    }

    // ====== MODALS ======
    let modalSeq = 0;
    function showModal(title, fieldsHtml, onSubmit, onClose) {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        const card = document.createElement('div');
        card.className = 'glass modal-card';
        const titleId = 'modalTitle' + (++modalSeq);
        card.setAttribute('role', 'dialog');
        card.setAttribute('aria-modal', 'true');
        card.setAttribute('aria-labelledby', titleId);
        card.innerHTML = `
            <div class="modal-hd">
                <h3 class="modal-title" id="${titleId}">${title}</h3>
                <button id="modalCloseBtn" class="btn btn-ghost btn-sm modal-close" aria-label="Close">✕</button>
            </div>
            <div class="modal-body">${fieldsHtml}</div>
            <div class="modal-ft">
                <button id="modalCancel" class="btn btn-ghost btn-sm">Cancel</button>
                <button id="modalOk" class="btn btn-primary btn-sm">Confirm</button>
            </div>
        `;
        overlay.appendChild(card);
        document.body.appendChild(overlay);
        const previouslyFocused = document.activeElement;
        const focusable = () => Array.from(card.querySelectorAll(
            'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href]'
        )).filter(el => el.offsetParent !== null);
        // Esc closes; Tab and Shift+Tab stay inside the dialog instead of reaching the page behind it.
        const onKeydown = e => {
            if (e.key === 'Escape') {
                e.stopPropagation();
                close();
            } else if (e.key === 'Tab') {
                const items = focusable();
                if (!items.length) return;
                const first = items[0], last = items[items.length - 1];
                if (!card.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
                else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
                else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
            }
        };
        const close = () => {
            document.removeEventListener('keydown', onKeydown, true);
            try { document.body.removeChild(overlay); } catch(e) {}
            // Give focus back to what opened the dialog (if it is still on the page).
            if (previouslyFocused && previouslyFocused.focus && document.body.contains(previouslyFocused)) {
                previouslyFocused.focus();
            }
            if (onClose) onClose();
        };
        document.addEventListener('keydown', onKeydown, true);
        overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
        card.querySelector('#modalCloseBtn').addEventListener('click', close);
        card.querySelector('#modalCancel').addEventListener('click', close);
        card.querySelector('#modalOk').addEventListener('click', async () => {
            try { await onSubmit(card); close(); } catch(e) {}
        });
        // Start on the first field; with no field (confirmations) start on the safe choice, Cancel.
        const firstField = card.querySelector('.modal-body input, .modal-body select, .modal-body textarea');
        (firstField || card.querySelector('#modalCancel')).focus();
        return card;
    }

    // Show a validation message inside the dialog (replaces the native alert()).
    function modalError(card, message) {
        let box = card.querySelector('.modal-error');
        if (!box) {
            box = document.createElement('div');
            box.className = 'modal-error';
            box.setAttribute('role', 'alert');
            card.querySelector('.modal-body').appendChild(box);
        }
        box.textContent = message;
    }

    // In-page replacement for confirm(): resolves true on Confirm, false on Cancel/close.
    function confirmDialog(title, message) {
        return new Promise(resolve => {
            showModal(title, `<p class="modal-message">${escapeHtml(message)}</p>`,
                async () => { resolve(true); },
                () => resolve(false));
        });
    }

    // ====== USER CRUD ======
    // Fill the PIN field (add-user by default; the edit dialog passes its own selector) with a random PIN that nobody else has (chosen by the server).
    async function fillGeneratedPin(card, pinSelector = '#um_pin') {
        const input = card.querySelector(pinSelector);
        const hint = card.querySelector('#um_pin_hint');
        const confirmBtn = card.querySelector('#modalOk');
        const length = card.querySelector('#um_pinlen').value;
        // Only the latest click may update the form: an older, slower response must not overwrite it.
        const requestId = (card.pinRequestId || 0) + 1;
        card.pinRequestId = requestId;
        hint.textContent = '';
        // Block saving while a PIN is on its way, so what is saved is what the admin is looking at.
        if (confirmBtn) confirmBtn.disabled = true;
        try {
            const res = await fetch('/admin/generate-pin?length=' + encodeURIComponent(length), {
                credentials: 'same-origin',
                cache: 'no-store'
            });
            const data = await res.json().catch(() => ({}));
            if (requestId !== card.pinRequestId) return;
            if (!res.ok || !data.pin) {
                hint.textContent = data.error || 'Could not generate a PIN';
                return;
            }
            input.value = data.pin;
            input.type = 'text'; // show it: the admin has to pass it on to the user
            hint.textContent = 'Generated a ' + data.pin.length + '-digit PIN that no one else uses. '
                + 'Write it down before saving.';
        } catch (e) {
            if (requestId !== card.pinRequestId) return;
            hint.textContent = 'Could not generate a PIN';
        } finally {
            if (confirmBtn && requestId === card.pinRequestId) confirmBtn.disabled = false;
        }
    }

    function openAddUser() {
        const card = showModal('Add User', `
            <label class="modal-field-label">Username</label>
            <input id="um_username" class="modal-input" placeholder="letters, numbers, _-.">
            <label class="modal-field-label">PIN (4–8 digits)</label>
            <div class="modal-pin-row">
                <input id="um_pin" class="modal-input" type="password" inputmode="numeric" pattern="[0-9]*" placeholder="e.g. 1234">
                <select id="um_pinlen" class="modal-input modal-pinlen" title="Length of the generated PIN">
                    <option value="4">4</option><option value="5">5</option><option value="6" selected>6</option>
                    <option value="7">7</option><option value="8">8</option>
                </select>
                <button id="um_generate" type="button" class="btn btn-ghost btn-sm">🎲 Generate</button>
            </div>
            <div id="um_pin_hint" class="modal-hint"></div>
        `, async card => {
            const username = card.querySelector('#um_username').value.trim();
            const pin = card.querySelector('#um_pin').value.trim();
            if (!username) { modalError(card, 'Username required'); throw new Error(); }
            if (!/^[-_.A-Za-z0-9]{1,32}$/.test(username)) { modalError(card, 'Invalid username'); throw new Error(); }
            if (!/^\d{4,8}$/.test(pin)) { modalError(card, 'PIN must be 4-8 digits'); throw new Error(); }
            // No new PIN while the one being saved is in flight.
            const generateBtn = card.querySelector('#um_generate');
            generateBtn.disabled = true;
            try { await addUser(username, pin); } finally { generateBtn.disabled = false; }
        });
        card.querySelector('#um_generate').addEventListener('click', () => fillGeneratedPin(card));
    }

    async function addUser(username, pin) {
        try {
            const res = await fetch('/admin/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                credentials: 'same-origin',
                cache: 'no-store',
                body: JSON.stringify({ username, pin, active: true }),
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                showToast('Create failed: ' + (err.error || res.status), 'error'); return;
            }
            showToast('User created', 'success');
            await loadUsers();
        } catch(e) { showToast('Create failed', 'error'); }
    }

    function openEditUser(username) {
        const card = showModal('Edit User', `
            <div class="modal-desc-sm">
                Update PIN for <strong class="modal-hl">${escapeHtml(username)}</strong>
            </div>
            <label class="modal-field-label">New PIN (optional)</label>
            <div class="modal-pin-row">
                <input id="um_newpin" class="modal-input" type="password" inputmode="numeric" pattern="[0-9]*" placeholder="leave blank to keep current">
                <select id="um_pinlen" class="modal-input modal-pinlen" title="Length of the generated PIN">
                    <option value="4">4</option><option value="5">5</option><option value="6" selected>6</option>
                    <option value="7">7</option><option value="8">8</option>
                </select>
                <button id="um_generate" type="button" class="btn btn-ghost btn-sm">🎲 Generate</button>
            </div>
            <div id="um_pin_hint" class="modal-hint"></div>
        `, async card => {
            const pin = card.querySelector('#um_newpin').value.trim();
            if (pin && !/^\d{4,8}$/.test(pin)) { showToast('PIN must be 4-8 digits', 'error'); throw new Error(); }
            // No new PIN while the one being saved is in flight.
            const generateBtn = card.querySelector('#um_generate');
            generateBtn.disabled = true;
            try { await editUser(username, pin || undefined); } finally { generateBtn.disabled = false; }
        });
        card.querySelector('#um_generate').addEventListener('click', () => fillGeneratedPin(card, '#um_newpin'));
    }

    async function editUser(username, pin) {
        try {
            const body = {};
            if (pin !== undefined) body.pin = pin;
            const res = await fetch('/admin/users/' + encodeURIComponent(username), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                credentials: 'same-origin',
                cache: 'no-store',
                body: JSON.stringify(body),
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                showToast('Update failed: ' + (err.error || res.status), 'error'); return;
            }
            showToast('User updated', 'success');
            await loadUsers();
        } catch(e) { showToast('Update failed', 'error'); }
    }

    async function toggleActive(username, active) {
        try {
            const res = await fetch('/admin/users/' + encodeURIComponent(username), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                credentials: 'same-origin',
                cache: 'no-store',
                body: JSON.stringify({ active }),
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                showToast('Toggle failed: ' + (err.error || res.status), 'error'); return;
            }
            showToast('User ' + (active ? 'activated' : 'deactivated'), 'success');
            await loadUsers();
        } catch(e) { showToast('Toggle failed', 'error'); }
    }

    function deleteUser(username) {
        showModal(`Delete user "${escapeHtml(username)}"`, `
            <div class="modal-desc">
                Permanently delete <strong class="modal-hl">${escapeHtml(username)}</strong> and all their access data.
            </div>
            <div class="modal-warn">This action cannot be undone.</div>
        `, async () => { await _doDeleteUser(username); });
    }

    async function _doDeleteUser(username) {
        try {
            const res = await fetch('/admin/users/' + encodeURIComponent(username), {
                method: 'DELETE',
                headers: { 'X-CSRF-Token': csrfToken },
                credentials: 'same-origin',
                cache: 'no-store',
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                showToast('Delete failed: ' + (err.error || res.status), 'error'); return;
            }
            showToast('User deleted', 'success');
            await loadUsers();
        } catch(e) { showToast('Delete failed', 'error'); }
    }

    function openMigrateAll(btnId) {
        showModal('Migrate All Users', `
            <div class="modal-desc">
                This will migrate all users from <code class="modal-code">config.ini</code> [pins] to the JSON user store using their existing PINs.
            </div>
            <div class="modal-warn">This action cannot be undone.</div>
        `, async () => { await migrateAll(btnId); });
    }

    async function migrateAll(btnId) {
        try {
            const restore = setButtonBusy(btnId, 'Migrating…');
            const res = await fetch('/admin/users/migrate-all', {
                method: 'POST',
                headers: { 'X-CSRF-Token': csrfToken },
                credentials: 'same-origin',
                cache: 'no-store'
            });
            const data = await res.json().catch(() => ({}));
            if (res.ok || res.status === 207) {
                const migrated = data.migrated || 0;
                const failed = (data.failed || []).length;
                showToast(`Migrated ${migrated} user(s)` + (failed ? `, ${failed} failed` : ''), failed ? 'error' : 'success');
                await loadUsers();
            } else {
                showToast('Migrate-all failed: ' + (data.error || res.status), 'error');
            }
            if (typeof restore === 'function') restore();
        } catch(e) { showToast('Migrate-all failed', 'error'); }
    }

    function openClearAll(btnId) {
        showModal('Clear All Logs', `
            <div class="modal-desc">
                This will permanently remove all log entries.
            </div>
            <div class="modal-warn">This action cannot be undone.</div>
        `, async () => { await clearLogs('all', btnId); });
    }

    async function clearLogs(mode, btnId) {
        try {
            const restore = setButtonBusy(btnId, 'Clearing…');
            const res = await fetch('/admin/logs/clear', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                credentials: 'same-origin',
                cache: 'no-store',
                body: JSON.stringify({ mode })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showToast('Clear logs failed: ' + (data.error || res.status), 'error');
                if (typeof restore === 'function') restore(); return;
            }
            showToast('All logs cleared', 'success');
            await loadLogs();
            if (typeof restore === 'function') restore();
        } catch(e) { showToast('Clear logs failed', 'error'); }
    }

    // ====== HELPERS ======
    function escapeHtml(str) {
        if (str == null) return '';
        return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function setButtonBusy(id, label) {
        if (!id) return null;
        const el = document.getElementById(id);
        if (!el) return null;
        const orig = el.dataset.origLabel || el.textContent;
        el.dataset.origLabel = orig;
        el.disabled = true;
        el.style.opacity = '0.6';
        el.textContent = label || 'Working…';
        return () => { el.disabled = false; el.style.opacity = ''; el.textContent = el.dataset.origLabel || orig; };
    }

    function _compareVersions(a, b) {
        const pa = a.split('.').map(Number);
        const pb = b.split('.').map(Number);
        for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
            const diff = (pa[i] || 0) - (pb[i] || 0);
            if (diff !== 0) return diff;
        }
        return 0;
    }

    function checkForUpdate(currentVersion) {
        if (!currentVersion || sessionStorage.getItem('updateChecked')) return;
        sessionStorage.setItem('updateChecked', '1');
        fetch('https://api.github.com/repos/Sloth-on-meth/DoorOpener/releases/latest', { cache: 'no-store' })
            .then(r => r.ok ? r.json() : null)
            .then(data => {
                if (!data || !data.tag_name) return;
                const latest = data.tag_name.replace(/^v/, '');
                if (_compareVersions(latest, currentVersion) > 0) {
                    const container = document.getElementById('toast-container');
                    if (!container) return;
                    const t = document.createElement('div');
                    t.className = 'toast info';
                    const a = document.createElement('a');
                    a.href = data.html_url || 'https://github.com/Sloth-on-meth/DoorOpener/releases';
                    a.target = '_blank';
                    a.rel = 'noopener noreferrer';
                    a.textContent = `Update available: v${latest}`;
                    t.appendChild(a);
                    container.appendChild(t);
                    setTimeout(() => t.classList.add('show'), 10);
                }
            })
            .catch(() => {});
    }

    function showToast(message, type = 'success') {
        const container = document.getElementById('toast-container');
        if (!container) return;
        const t = document.createElement('div');
        t.className = 'toast ' + type;
        t.textContent = message;
        container.appendChild(t);
        setTimeout(() => t.classList.add('show'), 10);
        setTimeout(() => {
            t.classList.remove('show');
            setTimeout(() => t.remove(), 380);
        }, 3500);
    }
