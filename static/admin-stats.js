/* Admin dashboard: renders the data from /admin/stats. Pure helpers are exported for tests. */
(function (root) {
    'use strict';

    const CATEGORY_ICON = { door: '🚪', security: '🛡', admin: '🔑', system: '⚠' };
    const BLOCK_LABELS = {
        SESSION_BLOCKED: 'Session blocks',
        IP_BLOCKED: 'IP blocks',
        BLOCK_ENFORCED: 'Tries while blocked',
        GLOBAL_THRESHOLD: 'Global limit reached',
    };
    const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const HOUR_LABELS = ['12a', '1a', '2a', '3a', '4a', '5a', '6a', '7a', '8a', '9a', '10a', '11a',
                         '12p', '1p', '2p', '3p', '4p', '5p', '6p', '7p', '8p', '9p', '10p', '11p'];

    function esc(value) {
        return String(value == null ? '' : value).replace(/[&<>"']/g, c =>
            ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

    function fmtHour(h) { return String(h).padStart(2, '0') + ':00'; }

    // "5 min ago", "3 h ago", "2 d ago"; older than a week falls back to the date.
    function ago(iso, nowMs) {
        const t = Date.parse(iso);
        if (isNaN(t)) return '';
        const sec = Math.max(0, Math.round(((nowMs == null ? Date.now() : nowMs) - t) / 1000));
        if (sec < 60) return 'just now';
        if (sec < 3600) return Math.floor(sec / 60) + ' min ago';
        if (sec < 86400) return Math.floor(sec / 3600) + ' h ago';
        if (sec < 7 * 86400) return Math.floor(sec / 86400) + ' d ago';
        return new Date(t).toLocaleDateString();
    }

    // Opacity of a heatmap cell: empty cells stay faint, the busiest one is solid.
    function heatAlpha(value, max) {
        if (!value || !max) return 0.06;
        return Math.round((0.2 + 0.8 * value / max) * 100) / 100;
    }

    // "Tue 14" style label for a YYYY-MM-DD date (parsed as local, so it never shifts a day).
    function dayLabel(isoDate) {
        const [y, m, d] = isoDate.split('-').map(Number);
        const date = new Date(y, m - 1, d);
        return { weekday: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][date.getDay()], day: d };
    }

    function byId(id) { return document.getElementById(id); }

    // The page's CSP forbids inline style="" attributes (they are silently dropped), so markup
    // carries data-* values and the styles are applied through the DOM instead.
    function applyStyles(root) {
        root.querySelectorAll('[data-w]').forEach(el => { el.style.width = el.dataset.w + '%'; });
        root.querySelectorAll('[data-heat]').forEach(el => {
            el.style.background = 'rgba(105,240,174,' + el.dataset.heat + ')';
        });
    }
    function setText(id, text) { const el = byId(id); if (el) el.textContent = text; }

    // ---- top cards ---------------------------------------------------------------------------
    function renderKpis(stats) {
        const d = stats.door;
        setText('statOpensToday', d.opens_today);
        setText('statOpensTodaySub', '7 days: ' + d.opens_7d + ' · 30 days: ' + d.opens_30d);
        setText('statRate', d.success_rate == null ? '—' : Math.round(d.success_rate) + '%');
        setText('statRateSub', d.attempts
            ? plural(d.denied, 'denial', 'denials') + ' · ' + plural(d.faults, 'fault', 'faults')
            : 'no attempts yet');
        setText('statBusy', d.busiest_hour ? fmtHour(d.busiest_hour.hour) : '—');
        setText('statBusySub', d.busiest_weekday ? d.busiest_weekday.weekday + 's are busiest' : 'not enough data');
        setText('statBlocked', stats.security.blocks_24h);
        setText('statBlockedSub', stats.security.blocks + ' in total');
    }

    // ---- bar charts: green = opened, red = denied (the bar's full height is both together) ----
    function renderBars(container, items) {
        const BAR_H = 140;
        const max = Math.max(1, ...items.map(i => i.ok + i.bad));
        container.innerHTML = '';
        items.forEach(item => {
            const total = item.ok + item.bad;
            const barPx = total ? Math.max(2, Math.round(total / max * BAR_H)) : 0;
            const okPx = total ? Math.round(item.ok / total * barPx) : 0;
            const col = document.createElement('div');
            col.className = 'chart-col';
            col.title = item.title;
            col.innerHTML = '<div class="chart-bars"><div class="chart-bar"><div class="chart-bar-ok"></div></div></div>'
                + '<div class="chart-lbl' + (item.now ? ' chart-lbl-now' : '') + (item.weekend ? ' chart-lbl-weekend' : '') + '">'
                + esc(item.label) + '</div>';
            col.querySelector('.chart-bar').style.height = barPx + 'px';
            col.querySelector('.chart-bar-ok').style.height = okPx + 'px';
            container.appendChild(col);
        });
    }

    function renderDaily(stats) {
        const todayIso = stats.door.daily.length ? stats.door.daily[stats.door.daily.length - 1].date : '';
        renderBars(byId('dailyChart'), stats.door.daily.map(day => {
            const l = dayLabel(day.date);
            return {
                label: String(l.day),
                weekend: l.weekday === 'Sat' || l.weekday === 'Sun',
                ok: day.opens,
                bad: day.denied,
                now: day.date === todayIso,
                title: l.weekday + ' ' + day.date + ': ' + plural(day.opens, 'opening', 'openings')
                    + ', ' + plural(day.denied, 'denial', 'denials'),
            };
        }));
    }

    function renderHourly(stats) {
        const nowHour = new Date().getHours();
        renderBars(byId('hourlyChart'), stats.door.hourly.map(h => ({
            label: HOUR_LABELS[h.hour],
            ok: h.opens,
            bad: h.denied,
            now: h.hour === nowHour,
            title: fmtHour(h.hour) + ': ' + plural(h.opens, 'opening', 'openings')
                + ', ' + plural(h.denied, 'denial', 'denials'),
        })));
    }

    // ---- weekday x hour heatmap --------------------------------------------------------------
    function renderHeatmap(stats) {
        const grid = stats.door.heatmap;
        const max = Math.max(0, ...grid.map(row => Math.max(...row)));
        const el = byId('heatmap');
        let html = '<div class="heat-corner"></div>';
        for (let h = 0; h < 24; h++) html += '<div class="heat-hour">' + (h % 3 === 0 ? h : '') + '</div>';
        grid.forEach((row, wd) => {
            html += '<div class="heat-day">' + WEEKDAYS[wd] + '</div>';
            row.forEach((v, h) => {
                html += '<div class="heat-cell" data-heat="' + heatAlpha(v, max) + '" title="'
                    + WEEKDAYS[wd] + ' ' + fmtHour(h) + ': ' + plural(v, 'opening', 'openings') + '"></div>';
            });
        });
        el.innerHTML = html;
        applyStyles(el);
    }

    // ---- lists -------------------------------------------------------------------------------
    function renderTopUsers(stats) {
        const users = stats.door.top_users;
        const el = byId('topUsersList');
        if (!users.length) { el.innerHTML = '<div class="stat-empty">No door openings logged yet.</div>'; return; }
        const max = users[0].opens;
        el.innerHTML = users.map((u, i) => {
            const rank = i === 0 ? 'rank-1' : i === 1 ? 'rank-2' : i === 2 ? 'rank-3' : 'rank-n';
            return '<div class="lb-row"><div class="rank ' + rank + '">' + (i + 1) + '</div>'
                + '<div class="lb-name" title="last used ' + esc(ago(u.last_used)) + '">' + esc(u.user) + '</div>'
                + '<div class="lb-bar-wrap"><div class="lb-bar" data-w="' + Math.round(u.opens / max * 100) + '"></div></div>'
                + '<div class="lb-count">' + u.opens + '</div></div>';
        }).join('') + '<div class="stat-foot">' + plural(stats.door.unique_users, 'person', 'people')
            + ' opened the door' + (stats.door.via_sso ? ' · ' + stats.door.via_sso + ' via SSO' : '') + '</div>';
        applyStyles(el);
    }

    function kv(label, value) {
        return '<div class="kv"><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>';
    }

    function renderSecurity(stats) {
        const s = stats.security;
        let html = kv('Blocked requests', s.blocks + ' (' + s.blocks_24h + ' in 24 h)')
            + kv('Wrong or disabled PINs', stats.door.denied);
        const types = Object.keys(s.by_type);
        if (types.length) {
            html += '<div class="stat-sub-hd">By type</div>'
                + types.map(t => kv(BLOCK_LABELS[t] || t, s.by_type[t])).join('');
        }
        if (s.top_ips.length) {
            html += '<div class="stat-sub-hd">Most refused addresses</div>' + s.top_ips.map(ip => {
                const parts = [];
                if (ip.denied) parts.push(plural(ip.denied, 'denial', 'denials'));
                if (ip.blocked) parts.push(ip.blocked + ' blocked');
                if (ip.admin_failed) parts.push(ip.admin_failed + ' admin login');
                return '<div class="kv"><span class="mono">' + esc(ip.ip) + '</span><strong>' + esc(parts.join(' · ')) + '</strong></div>';
            }).join('');
        } else if (!s.blocks) {
            html += '<div class="stat-empty">✅ Nothing suspicious in this log.</div>';
        }
        byId('securityBox').innerHTML = html;
    }

    function renderAdminAndSystem(stats) {
        const a = stats.admin, sy = stats.system;
        let html = '<div class="stat-sub-hd">Admin</div>'
            + kv('Logins', a.logins + (a.failed_logins ? ' · ' + a.failed_logins + ' failed' : ''))
            + kv('Changes made', a.changes);
        if (a.last_login) html += kv('Last login', ago(a.last_login.timestamp));
        if (a.recent.length) {
            html += a.recent.map(r => '<div class="recent-row sev-' + esc(r.severity) + '"><span>' + esc(r.label)
                + (r.details ? ' <em>' + esc(r.details) + '</em>' : '') + '</span><span>' + esc(ago(r.timestamp)) + '</span></div>').join('');
        }
        html += '<div class="stat-sub-hd">System</div>';
        if (sy.errors) {
            html += kv('Failures to open', sy.errors + ' (' + sy.errors_7d + ' in 7 days)');
            if (sy.last_error) {
                html += '<div class="recent-row sev-bad"><span>' + esc(sy.last_error.label)
                    + (sy.last_error.details ? ' <em>' + esc(sy.last_error.details) + '</em>' : '')
                    + '</span><span>' + esc(ago(sy.last_error.timestamp)) + '</span></div>';
            }
        } else {
            html += '<div class="stat-empty">✅ No Home Assistant problems logged.</div>';
        }
        byId('adminBox').innerHTML = html;
    }

    function renderNote(stats) {
        const range = stats.first
            ? ' from ' + new Date(stats.first).toLocaleDateString() + ' to ' + new Date(stats.last).toLocaleDateString()
            : '';
        let text = 'Based on ' + plural(stats.entries, 'log entry', 'log entries') + range + '.';
        if (stats.test_mode_entries) text += ' ' + plural(stats.test_mode_entries, 'test-mode entry is', 'test-mode entries are') + ' not counted.';
        text += ' Clearing the logs resets these numbers.';
        setText('statsNote', text);
    }

    function render(stats) {
        renderKpis(stats);
        renderNote(stats);
        renderDaily(stats);
        renderHourly(stats);
        renderHeatmap(stats);
        renderTopUsers(stats);
        renderSecurity(stats);
        renderAdminAndSystem(stats);
    }

    const api = { render, renderKpis, esc, plural, fmtHour, ago, heatAlpha, dayLabel, CATEGORY_ICON };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else root.AdminStats = api;
})(typeof window !== 'undefined' ? window : globalThis);
