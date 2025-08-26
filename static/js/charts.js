/**
 * Chart Creation and Management Functions
 * Network Traffic Analyzer
 * Author: sharondelya
 * Description: Chart.js and Plotly.js chart creation and management
 */

// Chart configuration defaults
const CHART_DEFAULTS = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: {
            display: true,
            position: 'top',
            labels: {
                usePointStyle: true,
                padding: 20,
                font: {
                    family: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
                    size: 12
                }
            }
        },
        tooltip: {
            mode: 'index',
            intersect: false,
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            titleColor: '#ffffff',
            bodyColor: '#ffffff',
            borderColor: '#0d6efd',
            borderWidth: 1,
            cornerRadius: 8,
            displayColors: true
        }
    },
    scales: {
        x: {
            grid: {
                display: true,
                color: 'rgba(0, 0, 0, 0.1)'
            },
            ticks: {
                font: {
                    family: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
                    size: 11
                }
            }
        },
        y: {
            beginAtZero: true,
            grid: {
                display: true,
                color: 'rgba(0, 0, 0, 0.1)'
            },
            ticks: {
                font: {
                    family: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
                    size: 11
                }
            }
        }
    }
};

// Color schemes for charts
const COLOR_SCHEMES = {
    primary: ['#0d6efd', '#198754', '#dc3545', '#ffc107', '#6f42c1', '#fd7e14', '#20c997', '#6c757d'],
    protocol: {
        'TCP': '#0d6efd',
        'UDP': '#198754', 
        'HTTP': '#0dcaf0',
        'HTTPS': '#ffc107',
        'DNS': '#6f42c1',
        'ICMP': '#dc3545',
        'SSH': '#fd7e14',
        'FTP': '#20c997'
    },
    status: {
        'ACTIVE': '#198754',
        'CLOSED': '#6c757d',
        'TIMEOUT': '#ffc107',
        'ERROR': '#dc3545'
    }
};

/**
 * Create traffic timeline chart
 */
function createTrafficTrendsChart(ctx, data) {
    if (!ctx || !data || data.length === 0) {
        console.warn('Invalid data for traffic trends chart');
        return null;
    }

    const labels = data.map(item => {
        const date = new Date(item.timestamp);
        return date.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit',
            hour12: false 
        });
    });

    const packetData = data.map(item => item.packets || item.packet_count || 0);
    const bytesData = data.map(item => Math.round((item.bytes || item.total_bytes || 0) / 1024)); // Convert to KB
    const mbpsData = data.map(item => item.mbps || 0);

    const config = {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Packets',
                    data: packetData,
                    borderColor: COLOR_SCHEMES.primary[0],
                    backgroundColor: COLOR_SCHEMES.primary[0] + '20',
                    tension: 0.4,
                    borderWidth: 2,
                    fill: true,
                    yAxisID: 'y'
                },
                {
                    label: 'Data (KB)',
                    data: bytesData,
                    borderColor: COLOR_SCHEMES.primary[1],
                    backgroundColor: COLOR_SCHEMES.primary[1] + '20',
                    tension: 0.4,
                    borderWidth: 2,
                    fill: true,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            ...CHART_DEFAULTS,
            interaction: {
                mode: 'index',
                intersect: false
            },
            scales: {
                x: {
                    ...CHART_DEFAULTS.scales.x,
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    ...CHART_DEFAULTS.scales.y,
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Packets'
                    }
                },
                y1: {
                    ...CHART_DEFAULTS.scales.y,
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Data (KB)'
                    },
                    grid: {
                        drawOnChartArea: false
                    }
                }
            }
        }
    };

    return new Chart(ctx, config);
}

/**
 * Create protocol distribution chart
 */
function createProtocolDistributionChart(ctx, data) {
    if (!ctx || !data || data.length === 0) {
        console.warn('Invalid data for protocol distribution chart');
        return null;
    }

    const labels = data.map(item => item.protocol);
    const values = data.map(item => item.packets || item.packet_count || 0);
    const colors = labels.map(protocol => COLOR_SCHEMES.protocol[protocol] || COLOR_SCHEMES.primary[0]);

    const config = {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderColor: colors.map(color => color + 'CC'),
                borderWidth: 2,
                hoverBorderWidth: 3
            }]
        },
        options: {
            ...CHART_DEFAULTS,
            plugins: {
                ...CHART_DEFAULTS.plugins,
                legend: {
                    ...CHART_DEFAULTS.plugins.legend,
                    position: 'bottom'
                },
                tooltip: {
                    ...CHART_DEFAULTS.plugins.tooltip,
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.raw / total) * 100).toFixed(1);
                            return `${context.label}: ${context.raw.toLocaleString()} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    };

    return new Chart(ctx, config);
}

/**
 * Create protocol analysis chart for analytics page
 */
function createProtocolAnalysisChart(ctx, data) {
    if (!ctx || !data || data.length === 0) {
        console.warn('Invalid data for protocol analysis chart');
        return null;
    }

    const labels = data.map(item => item.protocol);
    const packetData = data.map(item => item.packet_count || 0);
    const byteData = data.map(item => (item.total_bytes || 0) / 1024 / 1024); // Convert to MB
    const colors = labels.map(protocol => COLOR_SCHEMES.protocol[protocol] || COLOR_SCHEMES.primary[0]);

    const config = {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Packets',
                    data: packetData,
                    backgroundColor: colors.map(color => color + '80'),
                    borderColor: colors,
                    borderWidth: 2,
                    yAxisID: 'y'
                },
                {
                    label: 'Data (MB)',
                    data: byteData,
                    backgroundColor: colors.map(color => color + '40'),
                    borderColor: colors.map(color => color + 'CC'),
                    borderWidth: 2,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            ...CHART_DEFAULTS,
            scales: {
                x: {
                    ...CHART_DEFAULTS.scales.x,
                    title: {
                        display: true,
                        text: 'Protocol'
                    }
                },
                y: {
                    ...CHART_DEFAULTS.scales.y,
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Packets'
                    }
                },
                y1: {
                    ...CHART_DEFAULTS.scales.y,
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Data (MB)'
                    },
                    grid: {
                        drawOnChartArea: false
                    }
                }
            }
        }
    };

    return new Chart(ctx, config);
}

/**
 * Create bandwidth utilization chart
 */
function createBandwidthChart(ctx) {
    // Generate sample bandwidth data for demonstration
    const now = new Date();
    const data = [];
    const labels = [];

    for (let i = 59; i >= 0; i--) {
        const time = new Date(now.getTime() - i * 60000); // 1 minute intervals
        labels.push(time.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit',
            hour12: false 
        }));
        
        // Simulate bandwidth usage with some randomness
        const baseUsage = 50 + Math.sin(i / 10) * 20;
        const randomVariation = (Math.random() - 0.5) * 30;
        data.push(Math.max(0, Math.min(100, baseUsage + randomVariation)));
    }

    const config = {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Bandwidth Usage (%)',
                data: data,
                borderColor: COLOR_SCHEMES.primary[2],
                backgroundColor: COLOR_SCHEMES.primary[2] + '20',
                tension: 0.4,
                borderWidth: 2,
                fill: true,
                pointRadius: 0,
                pointHoverRadius: 4
            }]
        },
        options: {
            ...CHART_DEFAULTS,
            plugins: {
                ...CHART_DEFAULTS.plugins,
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    ...CHART_DEFAULTS.scales.x,
                    display: false
                },
                y: {
                    ...CHART_DEFAULTS.scales.y,
                    max: 100,
                    ticks: {
                        callback: function(value) {
                            return value + '%';
                        }
                    }
                }
            }
        }
    };

    const chart = new Chart(ctx, config);

    // Update bandwidth stats
    const maxUsage = Math.max(...data);
    const avgUsage = data.reduce((a, b) => a + b, 0) / data.length;
    const currentUsage = data[data.length - 1];

    setTimeout(() => {
        const peakElement = document.getElementById('peakBandwidth');
        const avgElement = document.getElementById('avgBandwidth');
        const currentElement = document.getElementById('currentBandwidth');

        if (peakElement) peakElement.textContent = maxUsage.toFixed(1) + '%';
        if (avgElement) avgElement.textContent = avgUsage.toFixed(1) + '%';
        if (currentElement) currentElement.textContent = currentUsage.toFixed(1) + '%';
    }, 100);

    return chart;
}

/**
 * Create network heatmap using Plotly
 */
function createNetworkHeatmap(container) {
    if (!container) {
        console.warn('Invalid container for network heatmap');
        return;
    }

    // Generate sample heatmap data
    const hours = [];
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const data = [];

    // Generate 24 hours
    for (let i = 0; i < 24; i++) {
        hours.push(i.toString().padStart(2, '0') + ':00');
    }

    // Generate data for each day/hour combination
    for (let day = 0; day < 7; day++) {
        const dayData = [];
        for (let hour = 0; hour < 24; hour++) {
            // Simulate higher activity during business hours
            let activity = Math.random() * 100;
            if (hour >= 9 && hour <= 17 && day < 5) {
                activity = activity * 2 + 50; // Higher activity during business hours
            }
            if (hour >= 0 && hour <= 6) {
                activity = activity * 0.3; // Lower activity at night
            }
            dayData.push(Math.min(100, activity));
        }
        data.push(dayData);
    }

    const trace = {
        z: data,
        x: hours,
        y: days,
        type: 'heatmap',
        colorscale: [
            [0, '#f8f9fa'],
            [0.2, '#e9ecef'],
            [0.4, '#dee2e6'],
            [0.6, '#adb5bd'],
            [0.8, '#6c757d'],
            [1, '#495057']
        ],
        showscale: true,
        colorbar: {
            title: 'Activity Level',
            titleside: 'right'
        }
    };

    const layout = {
        title: {
            text: 'Network Activity by Time',
            font: { size: 14 }
        },
        xaxis: {
            title: 'Hour of Day',
            tickangle: -45
        },
        yaxis: {
            title: 'Day of Week'
        },
        margin: {
            l: 60,
            r: 60,
            t: 60,
            b: 80
        },
        font: {
            family: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
            size: 11
        }
    };

    const config = {
        responsive: true,
        displayModeBar: false
    };

    Plotly.newPlot(container, [trace], layout, config);
}

/**
 * Create flow status distribution chart
 */
function createFlowStatusChart(ctx, statusData) {
    if (!ctx || !statusData) {
        console.warn('Invalid data for flow status chart');
        return null;
    }

    const labels = Object.keys(statusData);
    const values = Object.values(statusData);
    const colors = labels.map(status => COLOR_SCHEMES.status[status] || COLOR_SCHEMES.primary[0]);

    const config = {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderColor: '#ffffff',
                borderWidth: 2
            }]
        },
        options: {
            ...CHART_DEFAULTS,
            plugins: {
                ...CHART_DEFAULTS.plugins,
                legend: {
                    ...CHART_DEFAULTS.plugins.legend,
                    position: 'bottom'
                }
            }
        }
    };

    return new Chart(ctx, config);
}

/**
 * Update existing chart with new data
 */
function updateChart(chart, newData) {
    if (!chart || !newData) {
        console.warn('Invalid chart or data for update');
        return;
    }

    chart.data = newData;
    chart.update('active');
}

/**
 * Destroy chart instance
 */
function destroyChart(chart) {
    if (chart && typeof chart.destroy === 'function') {
        chart.destroy();
    }
}

/**
 * Resize all charts (useful for responsive design)
 */
function resizeAllCharts(charts) {
    Object.values(charts).forEach(chart => {
        if (chart && typeof chart.resize === 'function') {
            chart.resize();
        }
    });
}

/**
 * Export chart as image
 */
function exportChartAsImage(chart, filename = 'chart.png') {
    if (!chart || !chart.canvas) {
        console.warn('Invalid chart for export');
        return;
    }

    const url = chart.canvas.toDataURL('image/png');
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
}

/**
 * Get chart configuration for a specific chart type
 */
function getChartConfig(type, data, options = {}) {
    const baseConfig = {
        responsive: true,
        maintainAspectRatio: false,
        ...CHART_DEFAULTS
    };

    switch (type) {
        case 'line':
            return {
                type: 'line',
                data: data,
                options: { ...baseConfig, ...options }
            };
        case 'bar':
            return {
                type: 'bar',
                data: data,
                options: { ...baseConfig, ...options }
            };
        case 'doughnut':
            return {
                type: 'doughnut',
                data: data,
                options: { ...baseConfig, ...options }
            };
        default:
            return {
                type: type,
                data: data,
                options: { ...baseConfig, ...options }
            };
    }
}

// Export functions for global access
window.chartUtils = {
    createTrafficTrendsChart,
    createProtocolDistributionChart,
    createProtocolAnalysisChart,
    createBandwidthChart,
    createNetworkHeatmap,
    createFlowStatusChart,
    updateChart,
    destroyChart,
    resizeAllCharts,
    exportChartAsImage,
    getChartConfig,
    COLOR_SCHEMES,
    CHART_DEFAULTS
};

console.log('Chart utilities loaded successfully - sharondelya Network Traffic Analyzer');
