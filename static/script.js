/**
 * SentinelFlow — Client-side Realtime Engine & UI Utilities
 */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Initialize Lucide Icons
    if (window.lucide) {
        window.lucide.createIcons();
    }

    // 2. Initialize Socket.IO Client for Live Updates
    initRealtimeSocket();

    // 3. Global Search Keyboard Shortcut (Ctrl+K or /)
    document.addEventListener("keydown", (e) => {
        if ((e.ctrlKey && e.key === "k") || (e.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName))) {
            e.preventDefault();
            const searchInput = document.getElementById("global-search-input");
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        }
    });
});

/**
 * Toast Notification Dispatcher
 */
function showToast(title, message, type = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `sentinel-toast ${type === "danger" ? "toast-danger" : (type === "success" ? "toast-success" : "")}`;

    const iconMap = {
        danger: "🚨",
        warning: "⚠️",
        success: "✅",
        info: "🛡️"
    };

    toast.innerHTML = `
        <div style="font-size: 20px;">${iconMap[type] || "🛡️"}</div>
        <div style="flex: 1;">
            <div style="font-weight: 600; font-size: 13.5px; color: var(--text);">${title}</div>
            <div style="font-size: 12.5px; color: var(--muted); margin-top: 2px;">${message}</div>
        </div>
        <button onclick="this.parentElement.remove()" style="background: none; border: none; cursor: pointer; color: var(--muted); font-size: 16px;">&times;</button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(50px)";
        setTimeout(() => toast.remove(), 300);
    }, 4500);
}

/**
 * Realtime Socket.IO Connection & Event Handlers
 */
function initRealtimeSocket() {
    if (typeof io === "undefined") {
        console.warn("Socket.IO client library not loaded.");
        return;
    }

    try {
        const socket = io();

        socket.on("connect", () => {
            console.log("[SentinelFlow] Real-time telemetry channel established.");
            const sensorStatus = document.getElementById("sensor-status-indicator");
            if (sensorStatus) {
                sensorStatus.innerHTML = '<span class="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping"></span><span class="text-xs font-semibold text-emerald-800">SENSOR ACTIVE</span>';
            }
        });

        socket.on("disconnect", () => {
            console.warn("[SentinelFlow] Real-time telemetry disconnected.");
            const sensorStatus = document.getElementById("sensor-status-indicator");
            if (sensorStatus) {
                sensorStatus.innerHTML = '<span class="w-2.5 h-2.5 rounded-full bg-amber-500"></span><span class="text-xs font-semibold text-amber-800">RECONNECTING...</span>';
            }
        });

        // Live Packet Stream Listener
        socket.on("traffic_packet", (packet) => {
            handleIncomingPacket(packet);
        });

        // High Severity Alert Trigger
        socket.on("new_alert", (alert) => {
            showToast(
                `Critical Threat: ${alert.attack_type}`,
                `Flagged from ${alert.source_ip} (Risk Score: ${alert.risk_score})`,
                "danger"
            );
        });

    } catch (err) {
        console.error("Socket initialization error:", err);
    }
}

/**
 * Updates UI DOM elements when a packet is streamed
 */
function handleIncomingPacket(packet) {
    // 1. Update live packet feed table if present
    const liveTableBody = document.getElementById("live-packet-feed-tbody");
    if (liveTableBody) {
        const row = document.createElement("tr");
        row.className = "border-b border-[#F3E5D8] hover:bg-[#FFF8F0] transition-colors text-xs";
        
        const isMalicious = packet.attack_type !== "Normal";
        const badgeColor = isMalicious ? "bg-red-100 text-red-700 border-red-200" : "bg-emerald-100 text-emerald-700 border-emerald-200";

        row.innerHTML = `
            <td class="py-2.5 px-3 font-mono text-[#8A7568]">${packet.timestamp || "Just now"}</td>
            <td class="py-2.5 px-3 font-mono font-medium">${packet.source_ip || "192.168.1.1"}</td>
            <td class="py-2.5 px-3 uppercase text-[#8A7568] font-semibold">${packet.protocol || "tcp"}</td>
            <td class="py-2.5 px-3 text-[#3B2F2A]">${packet.service || "http"}</td>
            <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded-full text-[11px] font-semibold border ${badgeColor}">
                    ${packet.attack_type}
                </span>
            </td>
            <td class="py-2.5 px-3 font-semibold ${packet.risk_score >= 60 ? 'text-red-600' : (packet.risk_score >= 30 ? 'text-amber-600' : 'text-emerald-600')}">
                ${packet.risk_score}
            </td>
        `;

        liveTableBody.insertBefore(row, liveTableBody.firstChild);

        // Keep at most 15 rows in live monitor
        if (liveTableBody.children.length > 15) {
            liveTableBody.removeChild(liveTableBody.lastChild);
        }
    }

    // 2. Increment counters if KPI elements exist
    const totalEl = document.getElementById("kpi-total-analyzed");
    if (totalEl) {
        let val = parseInt(totalEl.innerText.replace(/,/g, "")) || 0;
        totalEl.innerText = (val + 1).toLocaleString();
    }

    if (packet.attack_type !== "Normal") {
        const attackEl = document.getElementById("kpi-total-attacks");
        if (attackEl) {
            let val = parseInt(attackEl.innerText.replace(/,/g, "")) || 0;
            attackEl.innerText = (val + 1).toLocaleString();
        }
    }
}