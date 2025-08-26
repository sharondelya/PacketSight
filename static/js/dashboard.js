/**
 * Dashboard JavaScript Functions
 * Network Traffic Analyzer
 * Author: sharondelya
 * Description: Real-time dashboard functionality and data visualization
 */

// Global variables
let dashboardState = {
    autoRefresh: true,
    refreshInterval: 30000, // 30 seconds
    currentTimeRange: '24h',
    charts: {},
    lastUpdate: null
};

/**
 * Initialize dashboard when page loads
 */
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    setupEventListeners();
    startAutoRefresh();
});

/**
 * Initialize all dashboard components
 */
function initializeDashboard() {
    console.log('Initializing Network Traffic Analyzer Dashboard...');
    
    // Update timestamp
    updateTimestamps();
    
    // Initialize real-time stats
    updateRealTimeStats();
    
    // Setup periodic updates
    setInterval(updateRealTimeStats, dashboardState.refreshInterval);
    setInterval(updateTimestamps, 1000);
}

/**
 * Setup event listeners for dashboard interactions
 */
function setupEventListeners() {
    // Auto-refresh toggle
    const autoRefreshToggle = document.getElementById('autoRefreshToggle');
    if (autoRefreshToggle) {
        autoRefreshToggle.addEventListener('change', function() {
            dashboardState.autoRefresh = this.checked;
            if (dashboardState.autoRefresh) {
                startAutoRefresh();
            } else {
                stopAutoRefresh();
            }
        });
    }
    
    // Time range selectors
    document.querySelectorAll('.time-range-selector').forEach(selector => {
        selector.addEventListener('change', function() {
            dashboardState.currentTimeRange = this.value;
            updateChartsForTimeRange(this.value);
        });
    });
    
    // Activity filter buttons
    document.querySelectorAll('.activity-filters .btn').forEach(btn => {
        btn.addEventListener('click', function() {
            // Remove active class from all buttons
            document.querySelectorAll('.activity-filters .btn').forEach(b => 
                b.classList.remove('active'));
            // Add active class to clicked button
            this.classList.add('active');
            
            const filter = this.dataset.filter;
            filterActivityFeed(filter);
        });
    });
    
    // Metric card click handlers
    document.querySelectorAll('.metric-card').forEach(card => {
        card.addEventListener('click', function() {
            const metric = this.dataset.metric;
            if (metric) {
                navigateToMetricDetails(metric);
            }
        });
    });
}

/**
 * Update real-time statistics
 */
function updateRealTimeStats() {
    if (!dashboardState.autoRefresh) return;
    
    try {
        // Note: Following Flask guidelines to avoid fetch calls where possible
        // This would normally use server-side rendering or WebSockets for real-time updates
        console.log('Real-time stats update triggered');
        
        // Update last refresh timestamp
        dashboardState.lastUpdate = new Date();
        updateTimestamps();
        
        // Update status indicator
        updateStatusIndicator('active');
        
    } catch (error) {
        console.error('Error updating real-time stats:', error);
        updateStatusIndicator('error');
    }
}

/**
 * Update timestamp displays
 */
function updateTimestamps() {
    const now = new Date();
    
    // Update last update time in header
    const lastUpdateElement = document.getElementById('lastUpdate');
    if (lastUpdateElement) {
        lastUpdateElement.textContent = now.toLocaleTimeString('en-US', { hour12: false });
    }
    
    // Update last analysis time in analytics
    const lastAnalysisElement = document.getElementById('lastAnalysisTime');
    if (lastAnalysisElement) {
        lastAnalysisElement.textContent = now.toLocaleTimeString('en-US', { hour12: false });
    }
    
    // Update footer uptime
    const uptimeElement = document.getElementById('footerUptime');
    if (uptimeElement && window.pageLoadTime) {
        const uptime = Math.floor((Date.now() - window.pageLoadTime) / (1000 * 60 * 60));
        uptimeElement.textContent = uptime + 'h';
    }
}

/**
 * Update status indicator
 */
function updateStatusIndicator(status) {
    const statusDot = document.querySelector('.status-dot');
    if (!statusDot) return;
    
    // Remove all status classes
    statusDot.classList.remove('status-active', 'status-warning', 'status-danger');
    
    // Add appropriate class
    switch (status) {
        case 'active':
            statusDot.classList.add('status-active');
            break;
        case 'warning':
            statusDot.classList.add('status-warning');
            break;
        case 'error':
            statusDot.classList.add('status-danger');
            break;
    }
}

/**
 * Start auto-refresh functionality
 */
function startAutoRefresh() {
    if (dashboardState.refreshTimer) {
        clearInterval(dashboardState.refreshTimer);
    }
    
    dashboardState.refreshTimer = setInterval(() => {
        if (dashboardState.autoRefresh && document.visibilityState === 'visible') {
            updateRealTimeStats();
        }
    }, dashboardState.refreshInterval);
}

/**
 * Stop auto-refresh functionality
 */
function stopAutoRefresh() {
    if (dashboardState.refreshTimer) {
        clearInterval(dashboardState.refreshTimer);
        dashboardState.refreshTimer = null;
    }
}

/**
 * Navigate to metric details
 */
function navigateToMetricDetails(metric) {
    switch (metric) {
        case 'packets':
            window.location.href = '/packets';
            break;
        case 'flows':
            window.location.href = '/flows';
            break;
        case 'analytics':
            window.location.href = '/analytics';
            break;
        default:
            console.log('Unknown metric:', metric);
    }
}

/**
 * Filter activity feed based on selection
 */
function filterActivityFeed(filter) {
    const activityItems = document.querySelectorAll('.activity-item');
    
    activityItems.forEach(item => {
        const itemType = item.dataset.type || 'all';
        
        if (filter === 'all' || itemType === filter) {
            item.style.display = 'flex';
            item.style.animation = 'fadeIn 0.3s ease';
        } else {
            item.style.display = 'none';
        }
    });
}

/**
 * Update charts for new time range
 */
function updateChartsForTimeRange(timeRange) {
    console.log(`Updating charts for time range: ${timeRange}`);
    
    // This would typically trigger a page reload or server-side update
    // Following Flask guidelines to avoid client-side API calls
    const url = new URL(window.location);
    url.searchParams.set('time_range', timeRange);
    
    // Show loading indicator
    showLoadingState();
    
    // Redirect to update time range
    setTimeout(() => {
        window.location.href = url.toString();
    }, 500);
}

/**
 * Show loading state on dashboard
 */
function showLoadingState() {
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        if (!card.classList.contains('loading')) {
            card.classList.add('loading');
        }
    });
}

/**
 * Hide loading state
 */
function hideLoadingState() {
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        card.classList.remove('loading');
    });
}

/**
 * Handle visibility changes (page focus/blur)
 */
document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible') {
        // Resume updates when page becomes visible
        if (dashboardState.autoRefresh) {
            updateRealTimeStats();
        }
    }
});

/**
 * Handle window resize for responsive charts
 */
window.addEventListener('resize', function() {
    // Resize charts if they exist
    Object.keys(dashboardState.charts).forEach(chartKey => {
        const chart = dashboardState.charts[chartKey];
        if (chart && typeof chart.resize === 'function') {
            chart.resize();
        }
    });
});

/**
 * Cleanup function for page unload
 */
window.addEventListener('beforeunload', function() {
    stopAutoRefresh();
    
    // Cleanup charts
    Object.keys(dashboardState.charts).forEach(chartKey => {
        const chart = dashboardState.charts[chartKey];
        if (chart && typeof chart.destroy === 'function') {
            chart.destroy();
        }
    });
});

/**
 * Utility function to format bytes
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Utility function to format numbers
 */
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

/**
 * Utility function to get time ago string
 */
function getTimeAgo(timestamp) {
    const now = new Date();
    const time = new Date(timestamp);
    const diffInSeconds = Math.floor((now - time) / 1000);
    
    if (diffInSeconds < 60) {
        return `${diffInSeconds} seconds ago`;
    }
    if (diffInSeconds < 3600) {
        return `${Math.floor(diffInSeconds / 60)} minutes ago`;
    }
    if (diffInSeconds < 86400) {
        return `${Math.floor(diffInSeconds / 3600)} hours ago`;
    }
    return `${Math.floor(diffInSeconds / 86400)} days ago`;
}

/**
 * Export dashboard state for debugging
 */
function exportDashboardState() {
    return {
        ...dashboardState,
        timestamp: new Date().toISOString()
    };
}

// Make functions available globally for debugging
window.dashboardUtils = {
    exportState: exportDashboardState,
    formatBytes,
    formatNumber,
    getTimeAgo,
    updateRealTimeStats,
    startAutoRefresh,
    stopAutoRefresh
};

console.log('Dashboard JavaScript loaded successfully - sharondelya Network Traffic Analyzer');
