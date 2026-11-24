// ===================================================================
// SECURE IOT FIRMWARE UPDATE SYSTEM - JAVASCRIPT CONTROLLER
// Virtual IoT Device Simulator & Real-Time Monitoring
// ===================================================================

document.addEventListener('DOMContentLoaded', function () {
    let telemetryChart = null;
    let statusChart = null;
    let autoSimInterval = null;
    let autoSimActive = true;
    let currentInspectedDeviceId = null;

    // Bootstrap Modal instances
    const addDeviceModalEl = document.getElementById('addDeviceModal');
    const viewDeviceModalEl = document.getElementById('viewDeviceModal');
    const editDeviceModalEl = document.getElementById('editDeviceModal');
    const deleteDeviceModalEl = document.getElementById('deleteDeviceModal');

    const addDeviceModal = addDeviceModalEl ? new bootstrap.Modal(addDeviceModalEl) : null;
    const viewDeviceModal = viewDeviceModalEl ? new bootstrap.Modal(viewDeviceModalEl) : null;
    const editDeviceModal = editDeviceModalEl ? new bootstrap.Modal(editDeviceModalEl) : null;
    const deleteDeviceModal = deleteDeviceModalEl ? new bootstrap.Modal(deleteDeviceModalEl) : null;

    // ---------------------------------------------------------------
    // 1. Mobile Sidebar Toggle & Live Clock
    // ---------------------------------------------------------------
    const menuToggleBtn = document.getElementById('menuToggleBtn');
    const appSidebar = document.getElementById('appSidebar');

    if (menuToggleBtn && appSidebar) {
        menuToggleBtn.addEventListener('click', function () {
            appSidebar.classList.toggle('show');
        });

        document.addEventListener('click', function (event) {
            const isClickInside = appSidebar.contains(event.target) || menuToggleBtn.contains(event.target);
            if (!isClickInside && appSidebar.classList.contains('show')) {
                appSidebar.classList.remove('show');
            }
        });
    }

    function updateLiveClock() {
        const clockEl = document.getElementById('liveClock');
        if (clockEl) {
            const now = new Date();
            const dateStr = now.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
            const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
            clockEl.innerHTML = `<i class="bi bi-clock me-1 text-cyber-green"></i> ${dateStr} ${timeStr} IST`;
        }
    }
    setInterval(updateLiveClock, 1000);
    updateLiveClock();

    // ---------------------------------------------------------------
    // 2. Initialize Charts
    // ---------------------------------------------------------------
    function initCharts(devices) {
        if (!devices || devices.length === 0) return;

        const labels = devices.map(d => d.id);
        const moistureData = devices.map(d => d.soil_moisture || 0);
        const humidityData = devices.map(d => d.humidity || 0);

        // Calculate counts
        const onlineCount = devices.filter(d => d.status === 'ONLINE').length;
        const warningCount = devices.filter(d => d.status === 'WARNING').length;
        const offlineCount = devices.filter(d => d.status === 'OFFLINE').length;

        // 1. Telemetry Bar Chart
        const ctxTelemetry = document.getElementById('telemetryChart');
        if (ctxTelemetry) {
            if (telemetryChart) telemetryChart.destroy();
            telemetryChart = new Chart(ctxTelemetry, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Soil Moisture (%)',
                            data: moistureData,
                            backgroundColor: 'rgba(0, 255, 157, 0.75)',
                            borderColor: '#00ff9d',
                            borderWidth: 1,
                            borderRadius: 4
                        },
                        {
                            label: 'Humidity (%)',
                            data: humidityData,
                            backgroundColor: 'rgba(6, 182, 212, 0.75)',
                            borderColor: '#06b6d4',
                            borderWidth: 1,
                            borderRadius: 4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 600 },
                    plugins: {
                        legend: {
                            labels: { color: '#cbd5e1', font: { family: 'Plus Jakarta Sans', size: 11 } }
                        },
                        tooltip: {
                            backgroundColor: '#070c18',
                            titleColor: '#00ff9d',
                            bodyColor: '#fff',
                            borderColor: 'rgba(0, 255, 157, 0.3)',
                            borderWidth: 1
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255, 255, 255, 0.05)' },
                            ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } }
                        },
                        y: {
                            min: 0,
                            max: 100,
                            grid: { color: 'rgba(255, 255, 255, 0.05)' },
                            ticks: { color: '#94a3b8', callback: value => value + '%' }
                        }
                    }
                }
            });
        }

        // 2. Status Doughnut Chart
        const ctxStatus = document.getElementById('statusChart');
        if (ctxStatus) {
            if (statusChart) statusChart.destroy();
            statusChart = new Chart(ctxStatus, {
                type: 'doughnut',
                data: {
                    labels: ['Online', 'Warning', 'Offline'],
                    datasets: [{
                        data: [onlineCount, warningCount, offlineCount],
                        backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                        borderColor: '#080e1c',
                        borderWidth: 3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#cbd5e1', font: { family: 'Plus Jakarta Sans', size: 12 }, padding: 15 }
                        }
                    },
                    cutout: '68%'
                }
            });
        }
    }

    // Update charts with new data
    function updateCharts(devices) {
        if (!devices) return;

        if (telemetryChart) {
            telemetryChart.data.labels = devices.map(d => d.id);
            telemetryChart.data.datasets[0].data = devices.map(d => d.soil_moisture || 0);
            telemetryChart.data.datasets[1].data = devices.map(d => d.humidity || 0);
            telemetryChart.update('none'); // Update without full redraw
        }

        if (statusChart) {
            const onlineCount = devices.filter(d => d.status === 'ONLINE').length;
            const warningCount = devices.filter(d => d.status === 'WARNING').length;
            const offlineCount = devices.filter(d => d.status === 'OFFLINE').length;
            statusChart.data.datasets[0].data = [onlineCount, warningCount, offlineCount];
            statusChart.update('none');
        }
    }

    // ---------------------------------------------------------------
    // 3. Update DOM Elements with Latest Telemetry
    // ---------------------------------------------------------------
    function updateDOMWithDevices(devices) {
        if (!devices) return;

        let total = devices.length;
        let online = 0, warning = 0, offline = 0, auth = 0;

        devices.forEach(device => {
            if (device.status === 'ONLINE') online++;
            else if (device.status === 'WARNING') warning++;
            else if (device.status === 'OFFLINE') offline++;

            if (device.auth_status === 'AUTHENTICATED') auth++;

            // Update row in table if it exists
            const row = document.getElementById(`row-${device.id}`);
            if (row) {
                row.setAttribute('data-status', device.status);

                const tempEl = row.querySelector('.val-temp');
                const humidityEl = row.querySelector('.val-humidity');
                const moistureEl = row.querySelector('.val-moisture');
                const batteryEl = row.querySelector('.val-battery');
                const statusBadgeEl = row.querySelector('.val-status-badge');
                const authBadgeEl = row.querySelector('.val-auth-badge');

                if (tempEl) tempEl.textContent = device.temperature;
                if (humidityEl) humidityEl.textContent = device.humidity;
                if (moistureEl) moistureEl.textContent = device.soil_moisture;
                if (batteryEl) batteryEl.textContent = device.battery;

                if (statusBadgeEl) {
                    if (device.status === 'ONLINE') {
                        statusBadgeEl.className = 'badge badge-cyber badge-status-online val-status-badge';
                        statusBadgeEl.innerHTML = '<span class="pulse-dot" style="width: 6px; height: 6px;"></span> ONLINE';
                    } else if (device.status === 'WARNING') {
                        statusBadgeEl.className = 'badge badge-cyber badge-status-warning val-status-badge';
                        statusBadgeEl.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i> WARNING';
                    } else {
                        statusBadgeEl.className = 'badge badge-cyber badge-status-offline val-status-badge';
                        statusBadgeEl.innerHTML = '<i class="bi bi-slash-circle-fill"></i> OFFLINE';
                    }
                }

                if (authBadgeEl) {
                    if (device.auth_status === 'AUTHENTICATED') {
                        authBadgeEl.className = 'badge badge-cyber badge-auth-verified val-auth-badge';
                        authBadgeEl.innerHTML = '<i class="bi bi-shield-check"></i> RSA Verified';
                    } else if (device.auth_status === 'PENDING') {
                        authBadgeEl.className = 'badge badge-cyber badge-auth-pending val-auth-badge';
                        authBadgeEl.innerHTML = '<i class="bi bi-hourglass-split"></i> Pending';
                    } else {
                        authBadgeEl.className = 'badge badge-cyber badge-auth-unverified val-auth-badge';
                        authBadgeEl.innerHTML = '<i class="bi bi-shield-x"></i> Unverified';
                    }
                }
            }
        });

        // Update Stat Cards
        const statTotalEl = document.getElementById('statTotalDevices');
        const statBreakdownEl = document.getElementById('statStatusBreakdown');
        const statAuthEl = document.getElementById('statAuthCount');

        if (statTotalEl) statTotalEl.innerHTML = `${total} <span style="font-size: 0.9rem; color: var(--text-dim);">Simulated</span>`;
        if (statBreakdownEl) statBreakdownEl.textContent = `${online} Online • ${warning} Warning • ${offline} Offline`;
        if (statAuthEl) statAuthEl.innerHTML = `${auth}/${total} <span style="font-size: 0.9rem; color: var(--text-dim);">Verified</span>`;

        // If a device details modal is currently open, refresh its data too
        if (currentInspectedDeviceId && viewDeviceModalEl && viewDeviceModalEl.classList.contains('show')) {
            const curDevice = devices.find(d => d.id === currentInspectedDeviceId);
            if (curDevice) populateDetailsModal(curDevice);
        }

        // Apply any active table filters
        applyTableFilter();
    }

    // ---------------------------------------------------------------
    // 4. API Calls: Telemetry Simulation & Device Fetch
    // ---------------------------------------------------------------
    function simulateTelemetry(showSpinner = false) {
        const refreshIcon = document.getElementById('refreshSpinIcon');
        if (showSpinner && refreshIcon) refreshIcon.classList.add('spin-animation');

        fetch('/api/devices/telemetry/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        })
        .then(res => res.json())
        .then(data => {
            if (data.success && data.devices) {
                updateDOMWithDevices(data.devices);
                updateCharts(data.devices);
            }
        })
        .catch(err => console.error("Telemetry simulation error:", err))
        .finally(() => {
            if (showSpinner && refreshIcon) {
                setTimeout(() => refreshIcon.classList.remove('spin-animation'), 600);
            }
        });
    }

    function fetchAllDevices(initOnly = false) {
        fetch('/api/devices')
            .then(res => res.json())
            .then(data => {
                if (data.success && data.devices) {
                    if (initOnly) {
                        initCharts(data.devices);
                    } else {
                        updateDOMWithDevices(data.devices);
                        updateCharts(data.devices);
                    }
                }
            })
            .catch(err => console.error("Error fetching devices:", err));
    }

    // Initial fetch to setup charts
    fetchAllDevices(true);

    // Auto-simulation interval: ticks every 6 seconds
    function startAutoSimulation() {
        if (autoSimInterval) clearInterval(autoSimInterval);
        autoSimInterval = setInterval(() => {
            if (autoSimActive) simulateTelemetry(false);
        }, 6000);
    }
    startAutoSimulation();

    // Toggle Auto Simulation Button
    const toggleAutoSimBtn = document.getElementById('toggleAutoSimBtn');
    const simStatusBadge = document.getElementById('simStatusBadge');
    const toggleSimIcon = document.getElementById('toggleSimIcon');
    const toggleSimText = document.getElementById('toggleSimText');

    if (toggleAutoSimBtn) {
        toggleAutoSimBtn.addEventListener('click', function () {
            autoSimActive = !autoSimActive;
            if (autoSimActive) {
                simStatusBadge.className = 'badge bg-dark border border-secondary text-cyber-green font-mono py-2 px-3';
                simStatusBadge.innerHTML = '<span class="pulse-dot d-inline-block me-1"></span> AUTO-SIMULATION: ACTIVE (6s)';
                toggleSimIcon.className = 'bi bi-pause-fill';
                toggleSimText.textContent = 'Pause';
            } else {
                simStatusBadge.className = 'badge bg-dark border border-secondary text-muted font-mono py-2 px-3';
                simStatusBadge.innerHTML = '<i class="bi bi-pause-circle text-muted me-1"></i> SIMULATION PAUSED';
                toggleSimIcon.className = 'bi bi-play-fill';
                toggleSimText.textContent = 'Resume';
            }
        });
    }

    // Manual Refresh Telemetry Button
    const refreshTelemetryBtn = document.getElementById('refreshTelemetryBtn');
    if (refreshTelemetryBtn) {
        refreshTelemetryBtn.addEventListener('click', function () {
            simulateTelemetry(true);
        });
    }

    // ---------------------------------------------------------------
    // 5. Populate and Display View Details Modal
    // ---------------------------------------------------------------
    function populateDetailsModal(device) {
        if (!document.getElementById('detailDeviceId')) return;
        currentInspectedDeviceId = device.id;
        document.getElementById('detailDeviceId').textContent = device.id;
        document.getElementById('detailDeviceName').textContent = device.name;
        document.getElementById('detailDeviceType').textContent = device.type;
        document.getElementById('detailLocation').textContent = device.location;

        const statusBadge = document.getElementById('detailStatusBadge');
        if (device.status === 'ONLINE') {
            statusBadge.className = 'badge badge-cyber badge-status-online';
            statusBadge.innerHTML = '<span class="pulse-dot" style="width: 6px; height: 6px;"></span> ONLINE';
        } else if (device.status === 'WARNING') {
            statusBadge.className = 'badge badge-cyber badge-status-warning';
            statusBadge.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i> WARNING';
        } else {
            statusBadge.className = 'badge badge-cyber badge-status-offline';
            statusBadge.innerHTML = '<i class="bi bi-slash-circle-fill"></i> OFFLINE';
        }

        const authBadge = document.getElementById('detailAuthBadge');
        if (device.auth_status === 'AUTHENTICATED') {
            authBadge.className = 'badge badge-cyber badge-auth-verified';
            authBadge.innerHTML = '<i class="bi bi-shield-check"></i> RSA Verified';
        } else if (device.auth_status === 'PENDING') {
            authBadge.className = 'badge badge-cyber badge-auth-pending';
            authBadge.innerHTML = '<i class="bi bi-hourglass-split"></i> Pending Verification';
        } else {
            authBadge.className = 'badge badge-cyber badge-auth-unverified';
            authBadge.innerHTML = '<i class="bi bi-shield-x"></i> Unverified';
        }

        document.getElementById('detailFirmware').textContent = device.firmware_version;
        document.getElementById('detailTargetFirmware').textContent = device.target_version || device.firmware_version;
        document.getElementById('detailSoilMoisture').textContent = `${device.soil_moisture || 0}%`;
        document.getElementById('detailTemperature').textContent = `${device.temperature || 0}°C`;
        document.getElementById('detailHumidity').textContent = `${device.humidity || 0}%`;
        document.getElementById('detailWaterLevel').textContent = `${device.water_level || 0}%`;
        document.getElementById('detailPhRain').textContent = `pH ${device.soil_ph || '6.5'} • ${device.rainfall || '0.0'} mm/h`;
        document.getElementById('detailSignal').textContent = `${device.signal || -65} dBm (Simulated Mesh)`;
        document.getElementById('detailBattery').textContent = `${device.battery || 0}%`;
        document.getElementById('detailFingerprint').textContent = device.public_key_fingerprint || 'RSA-2048';
        document.getElementById('detailTimestamp').textContent = device.last_updated || new Date().toLocaleString();

        const detailAuthBtn = document.getElementById('detailAuthBtn');
        if (detailAuthBtn) detailAuthBtn.setAttribute('data-id', device.id);
    }

    // ---------------------------------------------------------------
    // 6. Action Button Event Delegation (View, Auth, Edit, Delete)
    // ---------------------------------------------------------------
    const devicesTableBody = document.getElementById('devicesTableBody');

    if (devicesTableBody) {
        devicesTableBody.addEventListener('click', function (e) {
            const btn = e.target.closest('button');
            if (!btn) return;

            const deviceId = btn.getAttribute('data-id');
            if (!deviceId) return;

            // 1. View Details Button
            if (btn.classList.contains('btn-view-device')) {
                fetch(`/api/devices/${deviceId}`)
                    .then(res => res.json())
                    .then(data => {
                        if (data.success && data.device) {
                            populateDetailsModal(data.device);
                            if (viewDeviceModal) viewDeviceModal.show();
                        }
                    })
                    .catch(err => alert("Failed to fetch device details: " + err));
            }

            // 2. Authenticate Device Button
            if (btn.classList.contains('btn-auth-device')) {
                authenticateDevice(deviceId);
            }

            // 3. Edit Device Button
            if (btn.classList.contains('btn-edit-device')) {
                fetch(`/api/devices/${deviceId}`)
                    .then(res => res.json())
                    .then(data => {
                        if (data.success && data.device) {
                            const d = data.device;
                            document.getElementById('editDeviceId').value = d.id;
                            document.getElementById('editDeviceIdTitle').textContent = d.id;
                            document.getElementById('editDeviceName').value = d.name;
                            document.getElementById('editDeviceType').value = d.type;
                            document.getElementById('editDeviceLocation').value = d.location;
                            document.getElementById('editDeviceStatus').value = d.status;
                            document.getElementById('editDeviceTargetVersion').value = d.target_version || d.firmware_version;
                            if (editDeviceModal) editDeviceModal.show();
                        }
                    })
                    .catch(err => alert("Failed to load device for editing: " + err));
            }

            // 4. Delete Device Button
            if (btn.classList.contains('btn-delete-device')) {
                document.getElementById('deleteDeviceIdSpan').textContent = deviceId;
                const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
                if (confirmDeleteBtn) confirmDeleteBtn.setAttribute('data-id', deviceId);
                if (deleteDeviceModal) deleteDeviceModal.show();
            }
        });
    }

    // Authenticate function
    function authenticateDevice(deviceId) {
        fetch(`/api/devices/${deviceId}/authenticate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                alert(`✓ Cryptographic Handshake Successful!\n\nNode: ${deviceId}\nProtocol: RSA-2048 PKCS#1v1.5\nStatus: AUTHENTICATED & ONLINE`);
                fetchAllDevices();
            } else {
                alert("Authentication failed: " + data.message);
            }
        })
        .catch(err => alert("Error communicating with authentication server: " + err));
    }

    // Modal Authenticate Button
    const detailAuthBtn = document.getElementById('detailAuthBtn');
    if (detailAuthBtn) {
        detailAuthBtn.addEventListener('click', function () {
            const deviceId = this.getAttribute('data-id');
            if (deviceId) {
                authenticateDevice(deviceId);
                if (viewDeviceModal) viewDeviceModal.hide();
            }
        });
    }

    // ---------------------------------------------------------------
    // 7. Form Submissions (Add Device & Edit Device & Delete)
    // ---------------------------------------------------------------
    
    // Add Device Form
    const addDeviceForm = document.getElementById('addDeviceForm');
    if (addDeviceForm) {
        addDeviceForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const formData = new FormData(addDeviceForm);
            const payload = Object.fromEntries(formData.entries());

            fetch('/api/devices', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    alert(`✓ Virtual Device ${data.device.id} provisioned successfully into the simulated mesh!`);
                    addDeviceForm.reset();
                    if (addDeviceModal) addDeviceModal.hide();
                    // Reload page or re-render
                    window.location.reload();
                } else {
                    alert("Error creating device: " + data.message);
                }
            })
            .catch(err => alert("Request failed: " + err));
        });
    }

    // Edit Device Form
    const editDeviceForm = document.getElementById('editDeviceForm');
    if (editDeviceForm) {
        editDeviceForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const deviceId = document.getElementById('editDeviceId').value;
            const formData = new FormData(editDeviceForm);
            const payload = Object.fromEntries(formData.entries());

            fetch(`/api/devices/${deviceId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    alert(`✓ Device ${deviceId} configuration updated successfully!`);
                    if (editDeviceModal) editDeviceModal.hide();
                    window.location.reload();
                } else {
                    alert("Error updating device: " + data.message);
                }
            })
            .catch(err => alert("Request failed: " + err));
        });
    }

    // Confirm Delete
    const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
    if (confirmDeleteBtn) {
        confirmDeleteBtn.addEventListener('click', function () {
            const deviceId = this.getAttribute('data-id');
            if (!deviceId) return;

            fetch(`/api/devices/${deviceId}`, {
                method: 'DELETE'
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    alert(`✓ Virtual device ${deviceId} removed from mesh inventory.`);
                    if (deleteDeviceModal) deleteDeviceModal.hide();
                    window.location.reload();
                } else {
                    alert("Error removing device: " + data.message);
                }
            })
            .catch(err => alert("Delete request failed: " + err));
        });
    }

    // ---------------------------------------------------------------
    // 8. Search & Filter Table
    // ---------------------------------------------------------------
    const deviceSearchInput = document.getElementById('deviceSearchInput');
    const statusFilterSelect = document.getElementById('statusFilterSelect');

    function applyTableFilter() {
        const query = deviceSearchInput ? deviceSearchInput.value.toLowerCase().trim() : '';
        const statusFilter = statusFilterSelect ? statusFilterSelect.value : 'ALL';
        const rows = document.querySelectorAll('#devicesTableBody tr');

        rows.forEach(row => {
            const id = (row.getAttribute('data-id') || '').toLowerCase();
            const type = (row.getAttribute('data-type') || '').toLowerCase();
            const status = row.getAttribute('data-status') || '';
            const textContent = row.textContent.toLowerCase();

            const matchesQuery = !query || id.includes(query) || type.includes(query) || textContent.includes(query);
            const matchesStatus = (statusFilter === 'ALL') || (status === statusFilter);

            if (matchesQuery && matchesStatus) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    if (deviceSearchInput) deviceSearchInput.addEventListener('input', applyTableFilter);
    if (statusFilterSelect) statusFilterSelect.addEventListener('change', applyTableFilter);
});
