        let batteryLevel = null;
        let currentPin = '';
        let isSubmitting = false;
        let autoSubmitTimer = null;
        let pinVisible = false; // never persisted: every page load starts hidden
        let blockCountdownTimer = null;
        let sendingDotsInterval = null;
        let consecutiveSuccesses = 0;
        let reportHintShown = false;

        function startSendingDots(display) {
            let count = 0;
            display.innerHTML = '<span class="pin-placeholder" id="sendingText">Sending</span>';
            sendingDotsInterval = setInterval(() => {
                count = (count + 1) % 4;
                const el = document.getElementById('sendingText');
                if (el) el.textContent = 'Sending' + '.'.repeat(count);
            }, 350);
        }

        function stopSendingDots() {
            if (sendingDotsInterval) {
                clearInterval(sendingDotsInterval);
                sendingDotsInterval = null;
            }
        }

        function addDigit(digit) {
            if (isSubmitting) return;
            if (currentPin.length < 8) {
                currentPin += digit;
                updatePinDisplay();

                // Easter egg
                if (DOOR_CONFIG.easterEgg && currentPin === '6767') {
                    if (autoSubmitTimer) { clearTimeout(autoSubmitTimer); autoSubmitTimer = null; }
                    triggerEasterEgg();
                    return;
                }

                // Haptic feedback
                if (window.navigator.vibrate) {
                    window.navigator.vibrate(30);
                }

                // Debounced auto-submit: wait until user pauses typing and length >= 4
                if (autoSubmitTimer) {
                    clearTimeout(autoSubmitTimer);
                    autoSubmitTimer = null;
                }
                if (currentPin.length >= 4) {
                    autoSubmitTimer = setTimeout(() => {
                        if (!isSubmitting && currentPin.length >= 4) {
                            openDoor();
                        }
                    }, 700);
                }
            }
        }

        function clearPin() {
            if (currentPin.length > 0) {
                currentPin = currentPin.slice(0, -1);
                updatePinDisplay();
                if (autoSubmitTimer) {
                    clearTimeout(autoSubmitTimer);
                    autoSubmitTimer = null;
                }

                // Haptic feedback
                if (window.navigator.vibrate) {
                    window.navigator.vibrate(30);
                }
            }
        }

        function updatePinDisplay() {
            const display = document.getElementById('pinDisplay');
            if (currentPin.length === 0) {
                display.innerHTML = '<span class="pin-placeholder">Enter PIN</span>';
            } else {
                let html = '';
                for (let i = 0; i < currentPin.length; i++) {
                    html += '<span class="pin-dot">' + (pinVisible ? currentPin[i] : '●') + '</span>';
                }
                display.innerHTML = html;
            }
        }

        let authStatus = { oidc_enabled: false, oidc_authenticated: false, require_pin_for_oidc: true };

        function triggerEasterEgg() {
            currentPin = '';
            updatePinDisplay();

            const overlay = document.createElement('div');
            overlay.id = 'easter-egg-overlay';
            overlay.innerHTML = `
                <canvas id="confetti-canvas"></canvas>
                <div class="egg-card">
                    <div class="egg-numbers">
                        <span class="egg-six">6</span>
                        <span class="egg-seven">7</span>
                    </div>
                    <div class="egg-sub">six &nbsp; seven</div>
                </div>
            `;
            document.body.appendChild(overlay);
            setTimeout(() => overlay.classList.add('egg-visible'), 10);

            launchConfetti(document.getElementById('confetti-canvas'));
            playEasterEggSound();

            document.body.classList.add('wobbling');
            setTimeout(() => document.body.classList.remove('wobbling'), 1850);

            if (window.navigator.vibrate) {
                // Pulse in sync with each seesaw bounce (0.45s period, 10 cycles)
                let pulses = 0;
                const vibeInterval = setInterval(() => {
                    window.navigator.vibrate(60);
                    if (++pulses >= 10) clearInterval(vibeInterval);
                }, 450);
            }

            setTimeout(() => {
                overlay.classList.remove('egg-visible');
                setTimeout(() => overlay.remove(), 450);
            }, 4500);
        }

        function launchConfetti(canvas) {
            if (!canvas) return;
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            const ctx = canvas.getContext('2d');
            const colors = ['#ff3b3b', '#00e676', '#2196F3', '#FFD700', '#FF69B4', '#00BCD4', '#FF9800'];
            const particles = Array.from({ length: 130 }, () => ({
                x: Math.random() * canvas.width,
                y: -10 - Math.random() * 300,
                r: 4 + Math.random() * 6,
                d: 1.2 + Math.random() * 2.2,
                color: colors[Math.floor(Math.random() * colors.length)],
                tilt: Math.random() * Math.PI * 2,
                tiltSpeed: (Math.random() - 0.5) * 0.14,
            }));
            let frame = 0;
            function draw() {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                let anyVisible = false;
                particles.forEach(p => {
                    if (p.y < canvas.height + 20) anyVisible = true;
                    ctx.save();
                    ctx.translate(p.x, p.y);
                    ctx.rotate(p.tilt);
                    ctx.fillStyle = p.color;
                    ctx.fillRect(-p.r / 2, -p.r / 2, p.r, p.r * 2.5);
                    ctx.restore();
                    p.y += p.d + Math.sin(frame * 0.05 + p.x) * 0.6;
                    p.x += Math.sin(frame * 0.03 + p.y * 0.01) * 0.9;
                    p.tilt += p.tiltSpeed;
                });
                frame++;
                if (anyVisible) requestAnimationFrame(draw);
            }
            draw();
        }

        function playEasterEggSound() {
            try {
                const ctx = new (window.AudioContext || window.webkitAudioContext)();
                const now = ctx.currentTime;
                // 8-bit "ta-daa" fanfare
                [[523, 0, 0.1], [523, 0.11, 0.1], [523, 0.22, 0.1], [415, 0.33, 0.1],
                 [523, 0.44, 0.16], [659, 0.61, 0.16], [784, 0.78, 0.45]].forEach(([freq, start, dur]) => {
                    const osc = ctx.createOscillator();
                    const gain = ctx.createGain();
                    osc.connect(gain);
                    gain.connect(ctx.destination);
                    osc.type = 'square';
                    osc.frequency.setValueAtTime(freq, now + start);
                    gain.gain.setValueAtTime(0, now + start);
                    gain.gain.linearRampToValueAtTime(0.16, now + start + 0.01);
                    gain.gain.exponentialRampToValueAtTime(0.001, now + start + dur);
                    osc.start(now + start);
                    osc.stop(now + start + dur + 0.05);
                });
            } catch (e) { }
        }

        function openDoor() {
            const pin = currentPin;

            // If OIDC is authenticated and PIN is not required, allow pinless open
            if (!pin) {
                if (authStatus.oidc_enabled && authStatus.oidc_authenticated && !authStatus.require_pin_for_oidc) {
                    return openDoorWithSSO();
                } else {
                    showStatus('Please enter a PIN', 'error');
                    return;
                }
            }

            if (isSubmitting) return; // Prevent concurrent submissions
            isSubmitting = true;
            setKeypadDisabled(true);
            if (autoSubmitTimer) { clearTimeout(autoSubmitTimer); autoSubmitTimer = null; }

            // Visual submitting state
            const submitBtn = document.getElementById('submitBtn');
            submitBtn.classList.add('submitting');
            submitBtn.textContent = '';
            const display = document.getElementById('pinDisplay');
            startSendingDots(display);
            document.getElementById('submit-overlay').style.display = 'block';

            let keepPin = false;

            // Send request to open door
            fetch('/open-door', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
                cache: 'no-store',
                body: JSON.stringify({ pin: pin })
            })
                .then(readDoorResponse)
                .then(({ status, data }) => {
                    setOfflineBanner(false);
                    if (status === 200 && data.status === 'success') {
                        const nameMatch = data.message && data.message.match(/Welcome home,?\s+([^!]+)!/);
                        const userName = nameMatch ? nameMatch[1].trim() : null;

                        // Play success sound and fancy vibration
                        playSuccessSound();
                        if (window.navigator.vibrate) {
                            // Fancy "ta-da" vibration pattern: short-long-short with crescendo
                            window.navigator.vibrate([50, 30, 150, 50, 80, 30, 200]);
                        }
                        showAccessPopup('accessGrantedPopup', userName);
                        flashContainer('grant');
                        onDoorSuccess();
                    } else {
                        if ((status === 429 || status === 401) && data && data.blocked_until) {
                            startBlockCountdown(data.blocked_until);
                        }
                        // Change button to red cross on failure
                        submitBtn.classList.remove('submitting');
                        submitBtn.style.background = 'linear-gradient(135deg, #dc3545, #c82333)';
                        submitBtn.textContent = '✗';

                        // Play failure sound and enhanced vibration
                        playFailureSound();
                        showAccessPopup('accessDeniedPopup', null, data && data.message ? data.message : 'Access Denied');
                        flashContainer('deny');
                        if (window.navigator.vibrate) {
                            // Enhanced failure vibration pattern: strong buzz with pauses
                            window.navigator.vibrate([200, 100, 200, 100, 300]);
                        }
                        onDoorFailure();
                    }
                })
                .catch(error => {
                    keepPin = reportRequestError(error);
                })
                .finally(() => {
                    stopSendingDots();
                    document.getElementById('submit-overlay').style.display = 'none';
                    // Reset button and clear PIN after attempt
                    setTimeout(() => {
                        submitBtn.classList.remove('submitting');
                        submitBtn.style.background = 'linear-gradient(135deg, #4CAF50, #45a049)';
                        submitBtn.textContent = '✓';

                        // Only clear the PIN once the server has answered; after a connection or server
                        // problem keep it so the retry is one tap.
                        if (!keepPin) currentPin = '';
                        updatePinDisplay();
                        setKeypadDisabled(false);
                        isSubmitting = false;
                    }, 1200);
                });
        }

        function openDoorWithSSO() {
            if (isSubmitting) return;
            isSubmitting = true;
            setKeypadDisabled(true);
            if (autoSubmitTimer) { clearTimeout(autoSubmitTimer); autoSubmitTimer = null; }
            const ssoDisplay = document.getElementById('pinDisplay');
            startSendingDots(ssoDisplay);
            document.getElementById('submit-overlay').style.display = 'block';
            // No PIN payload; rely on server-side OIDC session
            fetch('/open-door', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                cache: 'no-store',
                body: JSON.stringify({})
            })
                .then(readDoorResponse)
                .then(({ status, data }) => {
                    setOfflineBanner(false);
                    if (status === 200 && data.status === 'success') {
                        const nameMatch = data.message && data.message.match(/Welcome home,?\s+([^!]+)!/);
                        const userName = nameMatch ? nameMatch[1].trim() : null;
                        playSuccessSound();
                        showAccessPopup('accessGrantedPopup', userName);
                        flashContainer('grant');
                        if (window.navigator.vibrate) window.navigator.vibrate([50, 30, 150, 50, 80, 30, 200]);
                        onDoorSuccess();
                    } else {
                        if ((status === 429 || status === 401) && data && data.blocked_until) {
                            startBlockCountdown(data.blocked_until);
                        }
                        const submitBtn = document.getElementById('submitBtn');
                        submitBtn.style.background = 'linear-gradient(135deg, #dc3545, #c82333)';
                        submitBtn.textContent = '✗';
                        playFailureSound();
                        showAccessPopup('accessDeniedPopup', null, data && data.message ? data.message : 'Access Denied');
                        flashContainer('deny');
                        if (window.navigator.vibrate) window.navigator.vibrate([200, 100, 200, 100, 300]);
                        onDoorFailure();
                    }
                })
                .catch(error => { reportRequestError(error); })
                .finally(() => {
                    stopSendingDots();
                    document.getElementById('submit-overlay').style.display = 'none';
                    setTimeout(() => {
                        const submitBtn = document.getElementById('submitBtn');
                        submitBtn.style.background = 'linear-gradient(135deg, #4CAF50, #45a049)';
                        submitBtn.textContent = '✓';
                        setKeypadDisabled(false);
                        isSubmitting = false;
                    }, 1200);
                });
        }

        function escapeHtml(str) {
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        function onDoorSuccess() {
            consecutiveSuccesses++;
            if (DOOR_CONFIG.pushbullet) {
            if (!reportHintShown && consecutiveSuccesses >= 2) {
                reportHintShown = true;
                const toastContainer = document.getElementById('toast-container');
                const toast = document.createElement('div');
                toast.className = 'toast warn';
                toast.textContent = 'Door not opening? Report the issue in the bottom left';
                toastContainer.appendChild(toast);
                setTimeout(() => toast.classList.add('show'), 10);
                setTimeout(() => {
                    toast.classList.remove('show');
                    setTimeout(() => toast.remove(), 500);
                }, 6000);
            }
            }
        }

        function onDoorFailure() {
            consecutiveSuccesses = 0;
        }

        // --- connectivity: tell "can't reach the server" apart from "the server said no" ---
        function setOfflineBanner(show, message) {
            const banner = document.getElementById('offline-banner');
            if (!banner) return;
            if (message) banner.textContent = message;
            banner.hidden = !show;
        }

        const OFFLINE_MESSAGE = "You're offline. The door can't be opened until you're back online.";

        // Parse the response; a non-JSON body (e.g. a proxy's 502 page) is a server problem, not a denial.
        function readDoorResponse(response) {
            return response.json().then(
                data => ({ status: response.status, data }),
                () => { const e = new Error('bad response'); e.kind = 'server'; e.status = response.status; throw e; }
            );
        }

        // Show the right message for a failed request. Returns true when the PIN should be kept so a
        // retry is one tap (nothing reached the server, so nothing was judged).
        function reportRequestError(error) {
            if (error && error.kind === 'server') {
                setOfflineBanner(false);
                showStatus('Server problem (' + error.status + '). Please try again in a moment.', 'error');
            } else {
                setOfflineBanner(true, navigator.onLine === false
                    ? OFFLINE_MESSAGE
                    : "Can't reach the server. Check your connection and try again.");
            }
            return true;
        }

        function showStatus(message, type, persistent) {
            const toastContainer = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;
            toast.textContent = message;

            toastContainer.appendChild(toast);
            setTimeout(() => {
                toast.classList.add('show');
            }, 10);
            if (!persistent) {
                setTimeout(() => {
                    toast.classList.remove('show');
                    setTimeout(() => toast.remove(), 500);
                }, 3500);
            }
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

        function setKeypadDisabled(disabled) {
            document.querySelectorAll('.keypad-btn').forEach(btn => {
                btn.disabled = disabled;
            });
        }

        function startBlockCountdown(blockedUntilEpoch) {
            try {
                const container = document.getElementById('toast-container');
                if (!container || !blockedUntilEpoch) return;
                let el = document.getElementById('block-toast');
                if (!el) {
                    el = document.createElement('div');
                    el.id = 'block-toast';
                    el.className = 'toast error';
                    container.appendChild(el);
                    setTimeout(() => el.classList.add('show'), 10);
                }
                setKeypadDisabled(true);
                const update = () => {
                    const now = Date.now() / 1000;
                    const remaining = Math.max(0, Math.ceil(blockedUntilEpoch - now));
                    const mins = Math.floor(remaining / 60);
                    const secs = remaining % 60;
                    el.textContent = `Too many attempts. Try again in ${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
                    if (remaining <= 0) {
                        clearInterval(blockCountdownTimer);
                        blockCountdownTimer = null;
                        el.classList.remove('show');
                        setTimeout(() => el.remove(), 500);
                        setKeypadDisabled(false);
                    }
                };
                if (blockCountdownTimer) clearInterval(blockCountdownTimer);
                blockCountdownTimer = setInterval(update, 1000);
                update();
            } catch (e) { }
        }

        function updateBatteryLevel(level) {
            const container = document.getElementById('battery-container');
            const batteryFill = document.getElementById('battery-fill');
            const batteryLevelEl = document.getElementById('battery-level');
            if (level === null || level === undefined) {
                if (container) container.style.display = 'none';
                return;
            }
            if (container) container.style.display = 'flex';
            if (batteryLevelEl) batteryLevelEl.textContent = `${level}%`;
            if (!batteryFill) return;
            batteryFill.style.width = `${level}%`;
            if (level >= 80) {
                batteryFill.style.background = 'linear-gradient(90deg, #4CAF50 0%, #8BC34A 100%)';
            } else if (level >= 50) {
                batteryFill.style.background = 'linear-gradient(90deg, #8BC34A 0%, #CDDC39 100%)';
            } else if (level >= 20) {
                batteryFill.style.background = 'linear-gradient(90deg, #FFC107 0%, #FF9800 100%)';
            } else {
                batteryFill.style.background = 'linear-gradient(90deg, #F44336 0%, #E91E63 100%)';
            }
        }

        function fetchBatteryLevel() {
            fetch('/battery', { credentials: 'same-origin', cache: 'no-store' })
                .then(response => response.json())
                .then(data => {
                    updateBatteryLevel(data.level);
                })
                .catch(error => {
                    updateBatteryLevel(null);
                });
        }

        function playSuccessSound() {
            try {
                // Create AudioContext for Web Audio API
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();

                // Success sound: ascending chime with harmonics
                const playTone = (frequency, startTime, duration, volume = 0.3) => {
                    const oscillator = audioContext.createOscillator();
                    const gainNode = audioContext.createGain();

                    oscillator.connect(gainNode);
                    gainNode.connect(audioContext.destination);

                    oscillator.frequency.setValueAtTime(frequency, startTime);
                    oscillator.type = 'sine';

                    // Smooth volume envelope
                    gainNode.gain.setValueAtTime(0, startTime);
                    gainNode.gain.linearRampToValueAtTime(volume, startTime + 0.01);
                    gainNode.gain.exponentialRampToValueAtTime(0.01, startTime + duration);

                    oscillator.start(startTime);
                    oscillator.stop(startTime + duration);
                };

                const now = audioContext.currentTime;

                // "Ta-da" chord progression: C-E-G-C (262-330-392-523 Hz)
                playTone(262, now, 0.15, 0.2);        // C4 - short
                playTone(330, now + 0.08, 0.25, 0.25); // E4 - medium  
                playTone(392, now + 0.2, 0.3, 0.3);    // G4 - longer
                playTone(523, now + 0.35, 0.4, 0.35);  // C5 - longest, highest

                // Add subtle harmonics for richness
                playTone(523 * 2, now + 0.35, 0.2, 0.1); // Octave harmonic
            } catch (e) {
                // Audio API not supported, fail silently
            }
        }

        function playFailureSound() {
            try {
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                // Futuristic digital fail: rapid frequency modulation, metallic beeps, glitch
                const now = audioContext.currentTime;
                const glitch = (freqs, start, dur, vol) => {
                    freqs.forEach((f, i) => {
                        const osc = audioContext.createOscillator();
                        const gain = audioContext.createGain();
                        osc.connect(gain);
                        gain.connect(audioContext.destination);
                        osc.type = i % 2 === 0 ? 'triangle' : 'square';
                        osc.frequency.setValueAtTime(f, start + i * 0.02);
                        // Quick vibrato
                        if (osc.type === 'triangle') {
                            osc.frequency.linearRampToValueAtTime(f * 1.07, start + i * 0.02 + dur / 3);
                            osc.frequency.linearRampToValueAtTime(f, start + i * 0.02 + dur);
                        }
                        gain.gain.setValueAtTime(0, start + i * 0.02);
                        gain.gain.linearRampToValueAtTime(vol, start + i * 0.02 + 0.01);
                        gain.gain.exponentialRampToValueAtTime(0.01, start + i * 0.02 + dur);
                        osc.start(start + i * 0.02);
                        osc.stop(start + i * 0.02 + dur);
                    });
                };
                // Glitchy metallic sequence
                glitch([420, 1800, 666, 1337, 333, 888], now, 0.09, 0.19);
                glitch([210, 900, 333, 777], now + 0.13, 0.13, 0.13);
                glitch([120, 480], now + 0.28, 0.17, 0.09);
                // Short digital zap
                const osc = audioContext.createOscillator();
                const gain = audioContext.createGain();
                osc.type = 'sawtooth';
                osc.frequency.setValueAtTime(80, now + 0.38);
                gain.gain.setValueAtTime(0.13, now + 0.38);
                osc.connect(gain);
                gain.connect(audioContext.destination);
                osc.frequency.linearRampToValueAtTime(10, now + 0.45);
                gain.gain.linearRampToValueAtTime(0.01, now + 0.45);
                osc.start(now + 0.38);
                osc.stop(now + 0.45);
            } catch (e) { }
        }

        function flashContainer(type) {
            const c = document.querySelector('.container');
            if (!c) return;
            c.classList.remove('flash-grant', 'flash-deny');
            void c.offsetWidth; // reflow to restart animation
            c.classList.add(type === 'grant' ? 'flash-grant' : 'flash-deny');
            setTimeout(() => c.classList.remove('flash-grant', 'flash-deny'), 1400);
        }

        function showAccessPopup(id, name, errorMsg) {
            const popup = document.getElementById(id);
            if (!popup) return;
            clearInterval(popup._typeInterval);
            clearInterval(popup._blinkInterval);

            popup.style.display = 'block';
            setTimeout(() => popup.classList.add('visible'), 10);

            if (id === 'accessGrantedPopup') {
                const line1 = '> ACCESS_GRANTED';
                const line2 = name ? '> WELCOME, ' + name.toUpperCase() : null;
                let i = 0;
                popup.innerHTML = '<span class="scan-line"></span>_';

                popup._typeInterval = setInterval(() => {
                    i++;
                    popup.innerHTML = '<span class="scan-line"></span>' + line1.slice(0, i) + '_';
                    if (i >= line1.length) {
                        clearInterval(popup._typeInterval);
                        if (line2) {
                            setTimeout(() => {
                                let j = 0;
                                popup.innerHTML = '<span class="scan-line"></span>' + line1 + '<br>' + '_';
                                popup._typeInterval = setInterval(() => {
                                    j++;
                                    popup.innerHTML = '<span class="scan-line"></span>' + line1 + '<br>' + line2.slice(0, j) + '_';
                                    if (j >= line2.length) {
                                        clearInterval(popup._typeInterval);
                                        popup.innerHTML = '<span class="scan-line"></span>' + line1 + '<br>' + line2;
                                    }
                                }, 42);
                            }, 160);
                        } else {
                            let on = true;
                            popup._blinkInterval = setInterval(() => {
                                on = !on;
                                popup.innerHTML = '<span class="scan-line"></span>' + line1 + (on ? '_' : ' ');
                            }, 420);
                        }
                    }
                }, 48);
            } else if (id === 'accessDeniedPopup') {
                const line1 = '✕ ACCESS_DENIED';
                const line2 = errorMsg ? '> ' + errorMsg.toUpperCase() : null;
                const sl = '<span class="scan-line"></span>';
                let i = 0;
                popup.innerHTML = sl + '_';
                popup._typeInterval = setInterval(() => {
                    i++;
                    popup.innerHTML = sl + line1.slice(0, i) + '_';
                    if (i >= line1.length) {
                        clearInterval(popup._typeInterval);
                        if (line2) {
                            setTimeout(() => {
                                let j = 0;
                                popup.innerHTML = sl + line1 + '<br>_';
                                popup._typeInterval = setInterval(() => {
                                    j++;
                                    popup.innerHTML = sl + line1 + '<br>' + line2.slice(0, j) + '_';
                                    if (j >= line2.length) {
                                        clearInterval(popup._typeInterval);
                                        popup.innerHTML = sl + line1 + '<br>' + line2;
                                    }
                                }, 35);
                            }, 120);
                        } else {
                            popup.innerHTML = sl + line1;
                        }
                    }
                }, 40);
            }

            const hideDelay = id === 'accessGrantedPopup' ? 2800 : 2200;
            setTimeout(() => {
                clearInterval(popup._typeInterval);
                clearInterval(popup._blinkInterval);
                popup.classList.remove('visible');
                setTimeout(() => {
                    popup.style.display = 'none';
                    popup.innerHTML = '';
                }, 400);
            }, hideDelay);
        }


        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function () {
            // Register service worker for PWA install/offline support
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.register('/service-worker.js').catch(() => { /* ignore */ });
            }
            // Battery polling: refresh every 60s, but only while the tab is visible
            // so a backgrounded keypad doesn't keep hitting the server (and HA).
            let batteryPollTimer = null;
            function startBatteryPolling() {
                if (batteryPollTimer !== null) return;
                fetchBatteryLevel();
                batteryPollTimer = setInterval(fetchBatteryLevel, 60000);
            }
            function stopBatteryPolling() {
                if (batteryPollTimer === null) return;
                clearInterval(batteryPollTimer);
                batteryPollTimer = null;
            }
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) stopBatteryPolling();
                else startBatteryPolling();
            });
            if (!document.hidden) startBatteryPolling();

            // Check for a newer release on GitHub (non-blocking, once per session)
            checkForUpdate(DOOR_CONFIG.appVersion);

            // Query authentication status for OIDC UX
            fetch('/auth/status', { credentials: 'same-origin', cache: 'no-store' })
                .then(r => r.json())
                .then(s => {
                    authStatus = s || authStatus;
                    const loginBtn = document.getElementById('ssoLoginBtn');
                    const openBtn = document.getElementById('ssoOpenBtn');
                    const logoutBtn = document.getElementById('ssoLogoutBtn'); // Logout button

                    if (loginBtn && openBtn && logoutBtn) {
                        if (authStatus.oidc_enabled && authStatus.oidc_authenticated) {
                            loginBtn.style.display = 'none';
                            logoutBtn.style.display = 'block'; // Show Logout button
                            // Show Open with SSO only when PIN not required
                            openBtn.style.display = authStatus.require_pin_for_oidc ? 'none' : 'inline-block';
                        } else {
                            loginBtn.style.display = authStatus.oidc_enabled ? 'inline-block' : 'none';
                            openBtn.style.display = 'none';
                            logoutBtn.style.display = 'none'; // Hide Logout button
                        }
                    }
                })
                .catch(() => { });

            // Initialize PIN display
            updatePinDisplay();

            // Wire up keypad buttons
            document.querySelectorAll('.keypad-btn[data-digit]').forEach(btn => {
                btn.addEventListener('click', () => addDigit(btn.dataset.digit));
            });
            window.addEventListener('offline', () => setOfflineBanner(true, OFFLINE_MESSAGE));
            window.addEventListener('online', () => setOfflineBanner(false));
            if (navigator.onLine === false) setOfflineBanner(true, OFFLINE_MESSAGE);
            const pinToggle = document.getElementById('pinToggle');
            if (pinToggle) pinToggle.addEventListener('click', () => {
                pinVisible = !pinVisible;
                pinToggle.setAttribute('aria-pressed', String(pinVisible));
                pinToggle.setAttribute('aria-label', pinVisible ? 'Hide PIN' : 'Show PIN');
                pinToggle.title = pinVisible ? 'Hide PIN' : 'Show PIN';
                if (!isSubmitting) updatePinDisplay(); // don't overwrite the "Sending..." indicator
            });
            const clearBtn = document.getElementById('clearBtn');
            if (clearBtn) clearBtn.addEventListener('click', clearPin);
            const submitBtn2 = document.getElementById('submitBtn');
            if (submitBtn2) submitBtn2.addEventListener('click', () => { if (!isSubmitting) openDoor(); });
            const ssoOpenBtn = document.getElementById('ssoOpenBtn');
            if (ssoOpenBtn) ssoOpenBtn.addEventListener('click', openDoorWithSSO);
            const ssoLogoutBtn = document.getElementById('ssoLogoutBtn');
            if (ssoLogoutBtn) ssoLogoutBtn.addEventListener('click', () => { window.location.href = '/oidc/logout'; });

            // Add keyboard support; ignore auto-repeat when key is held down
            document.addEventListener('keydown', function (event) {
                // Don't intercept keys while focus is inside a text input/textarea
                const tag = document.activeElement && document.activeElement.tagName;
                if (tag === 'INPUT' || tag === 'TEXTAREA') return;

                if (event.repeat) {
                    event.preventDefault();
                    return;
                }
                if (event.key >= '0' && event.key <= '9') {
                    addDigit(event.key);
                    event.preventDefault();
                } else if (event.key === 'Backspace') {
                    clearPin();
                    event.preventDefault();
                } else if (event.key === 'Enter') {
                    if (!isSubmitting) openDoor();
                    event.preventDefault();
                }
            });
        });

        if (DOOR_CONFIG.pushbullet) {
        // Report a problem modal
        (function() {
            const overlay  = document.getElementById('reportModalOverlay');
            const openBtn  = document.getElementById('reportProblemBtn');
            const cancelBtn = document.getElementById('reportCancelBtn');
            const sendBtn  = document.getElementById('reportSendBtn');
            const msgEl    = document.getElementById('reportMsg');
            const textarea = document.getElementById('reportMessage');

            function openModal() {
                textarea.value = '';
                msgEl.textContent = '';
                msgEl.className = 'report-modal-msg';
                sendBtn.disabled = false;
                overlay.classList.add('open');
                setTimeout(() => textarea.focus(), 50);
            }
            function closeModal() { overlay.classList.remove('open'); }

            openBtn.addEventListener('click', openModal);
            cancelBtn.addEventListener('click', closeModal);
            overlay.addEventListener('click', function(e) {
                if (e.target === overlay) closeModal();
            });
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && overlay.classList.contains('open')) closeModal();
            });

            sendBtn.addEventListener('click', async function() {
                const message = textarea.value.trim();
                if (!message) { textarea.focus(); return; }
                sendBtn.disabled = true;
                msgEl.textContent = 'Sending…';
                msgEl.className = 'report-modal-msg';
                try {
                    const res = await fetch('/report-problem', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ message })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        msgEl.textContent = 'Report sent. Thank you!';
                        msgEl.className = 'report-modal-msg ok';
                        setTimeout(closeModal, 1800);
                    } else {
                        msgEl.textContent = data.error || 'Failed to send.';
                        msgEl.className = 'report-modal-msg err';
                        sendBtn.disabled = false;
                    }
                } catch (_) {
                    msgEl.textContent = 'Network error. Please try again.';
                    msgEl.className = 'report-modal-msg err';
                    sendBtn.disabled = false;
                }
            });
        })();
        }
