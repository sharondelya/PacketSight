/**
 * Analytics JavaScript Functions
 * Network Traffic Analyzer
 * Author: sharondelya
 * Description: Advanced analytics functionality and data visualization
 */

// Global analytics state
window.analyticsUtils = {
    charts: {},
    initialized: false
};

/**
 * Create advanced traffic trends visualization
 */
window.analyticsUtils.createAdvancedTrafficTrends = function(ctx, data) {
    if (!ctx || !data || data.length === 0) {
        console.log('No data available for traffic trends');
        return;
    }
    
    const labels = data.map(item => {
        const date = new Date(item.timestamp);
        return date.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit',
            hour12: false 
        });
    });
    
    const packetData = data.map(item => item.packets || 0);
    const bytesData = data.map(item => Math.round((item.bytes || 0) / 1024)); // Convert to KB
    
    window.analyticsUtils.charts.trafficTrends = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Packets per Hour',
                data: packetData,
                borderColor: '#0d6efd',
                backgroundColor: 'rgba(13, 110, 253, 0.1)',
                tension: 0.4,
                fill: true,
                yAxisID: 'y'
            }, {
                label: 'Data Volume (KB)',
                data: bytesData,
                borderColor: '#198754',
                backgroundColor: 'rgba(25, 135, 84, 0.1)',
                tension: 0.4,
                fill: true,
                yAxisID: 'y1'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            aspectRatio: 3,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Packets'
                    },
                    beginAtZero: true
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Data (KB)'
                    },
                    beginAtZero: true,
                    grid: {
                        drawOnChartArea: false,
                    },
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        title: function(context) {
                            return 'Time: ' + context[0].label;
                        },
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.datasetIndex === 0) {
                                label += context.raw.toLocaleString() + ' packets';
                            } else {
                                label += context.raw.toLocaleString() + ' KB';
                            }
                            return label;
                        }
                    }
                }
            }
        }
    });
};

/**
 * Create protocol analysis visualization
 */
window.analyticsUtils.createProtocolAnalysisVisualization = function(ctx, data) {
    if (!ctx || !data || data.length === 0) {
        console.log('No data available for protocol analysis');
        return;
    }
    
    const labels = data.map(item => item.protocol);
    const values = data.map(item => item.packet_count);
    const colors = [
        '#0d6efd', '#198754', '#dc3545', '#ffc107',
        '#6f42c1', '#fd7e14', '#20c997', '#6c757d',
        '#e83e8c', '#17a2b8'
    ];
    
    window.analyticsUtils.charts.protocolAnalysis = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors.slice(0, labels.length),
                borderWidth: 3,
                borderColor: '#ffffff',
                hoverBorderWidth: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            aspectRatio: 1.5,
            plugins: {
                legend: {
                    display: true,
                    position: 'right',
                    labels: {
                        usePointStyle: true,
                        padding: 20
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.raw / total) * 100).toFixed(1);
                            return context.label + ': ' + context.raw.toLocaleString() + ' packets (' + percentage + '%)';
                        }
                    }
                }
            }
        }
    });
};

/**
 * Generate network topology visualization using Plotly
 */
window.analyticsUtils.generateNetworkTopology = function(container, data) {
    if (!container) {
        console.error('Container element not found for network topology');
        return;
    }
    
    // Generate sample network topology data
    const nodes = [
        { x: 0.5, y: 0.8, name: 'Gateway', type: 'gateway', connections: 15 },
        { x: 0.2, y: 0.6, name: '192.168.1.100', type: 'internal', connections: 8 },
        { x: 0.8, y: 0.6, name: '192.168.1.101', type: 'internal', connections: 12 },
        { x: 0.1, y: 0.4, name: '8.8.8.8', type: 'external', connections: 25 },
        { x: 0.9, y: 0.4, name: '1.1.1.1', type: 'external', connections: 18 },
        { x: 0.3, y: 0.2, name: '74.125.224.72', type: 'external', connections: 22 },
        { x: 0.7, y: 0.2, name: '151.101.129.140', type: 'external', connections: 14 }
    ];
    
    const edges = [
        { from: 0, to: 1 }, { from: 0, to: 2 }, { from: 1, to: 3 },
        { from: 2, to: 4 }, { from: 1, to: 5 }, { from: 2, to: 6 }
    ];
    
    // Create traces for different node types
    const gatewayNodes = nodes.filter(n => n.type === 'gateway');
    const internalNodes = nodes.filter(n => n.type === 'internal');
    const externalNodes = nodes.filter(n => n.type === 'external');
    
    const traces = [];
    
    // Add edges
    const edgeX = [];
    const edgeY = [];
    edges.forEach(edge => {
        edgeX.push(nodes[edge.from].x, nodes[edge.to].x, null);
        edgeY.push(nodes[edge.from].y, nodes[edge.to].y, null);
    });
    
    traces.push({
        x: edgeX,
        y: edgeY,
        mode: 'lines',
        line: { width: 2, color: '#cccccc' },
        hoverinfo: 'none',
        showlegend: false
    });
    
    // Add gateway nodes
    if (gatewayNodes.length > 0) {
        traces.push({
            x: gatewayNodes.map(n => n.x),
            y: gatewayNodes.map(n => n.y),
            mode: 'markers+text',
            marker: {
                size: 20,
                color: '#dc3545',
                symbol: 'diamond'
            },
            text: gatewayNodes.map(n => n.name),
            textposition: 'top center',
            name: 'Gateway',
            hovertemplate: '<b>%{text}</b><br>Connections: %{customdata}<extra></extra>',
            customdata: gatewayNodes.map(n => n.connections)
        });
    }
    
    // Add internal nodes
    if (internalNodes.length > 0) {
        traces.push({
            x: internalNodes.map(n => n.x),
            y: internalNodes.map(n => n.y),
            mode: 'markers+text',
            marker: {
                size: 15,
                color: '#198754',
                symbol: 'circle'
            },
            text: internalNodes.map(n => n.name),
            textposition: 'top center',
            name: 'Internal',
            hovertemplate: '<b>%{text}</b><br>Connections: %{customdata}<extra></extra>',
            customdata: internalNodes.map(n => n.connections)
        });
    }
    
    // Add external nodes
    if (externalNodes.length > 0) {
        traces.push({
            x: externalNodes.map(n => n.x),
            y: externalNodes.map(n => n.y),
            mode: 'markers+text',
            marker: {
                size: 12,
                color: '#ffc107',
                symbol: 'square'
            },
            text: externalNodes.map(n => n.name),
            textposition: 'top center',
            name: 'External',
            hovertemplate: '<b>%{text}</b><br>Connections: %{customdata}<extra></extra>',
            customdata: externalNodes.map(n => n.connections)
        });
    }
    
    const layout = {
        title: {
            text: 'Network Topology Map',
            font: { size: 16 }
        },
        showlegend: true,
        legend: {
            x: 0,
            y: 1,
            bgcolor: 'rgba(255,255,255,0.8)'
        },
        xaxis: {
            showgrid: false,
            zeroline: false,
            showticklabels: false,
            range: [-0.1, 1.1]
        },
        yaxis: {
            showgrid: false,
            zeroline: false,
            showticklabels: false,
            range: [-0.1, 1.1]
        },
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)',
        margin: { l: 20, r: 20, t: 40, b: 20 },
        height: 400
    };
    
    const config = {
        displayModeBar: false,
        responsive: true
    };
    
    try {
        Plotly.newPlot(container, traces, layout, config);
        console.log('Network topology visualization created successfully');
    } catch (error) {
        console.error('Error creating network topology:', error);
        container.innerHTML = '<div class="text-center text-muted py-4">Failed to load network topology</div>';
    }
};

/**
 * Destroy all analytics charts
 */
window.analyticsUtils.destroyCharts = function() {
    Object.keys(window.analyticsUtils.charts).forEach(chartKey => {
        const chart = window.analyticsUtils.charts[chartKey];
        if (chart && typeof chart.destroy === 'function') {
            try {
                chart.destroy();
                console.log(`Chart ${chartKey} destroyed`);
            } catch (e) {
                console.log(`Error destroying chart ${chartKey}:`, e);
            }
        }
    });
    window.analyticsUtils.charts = {};
};

/**
 * Utility functions for analytics
 */
window.analyticsUtils.formatBytes = function(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

window.analyticsUtils.formatNumber = function(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
};

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (window.analyticsUtils) {
        window.analyticsUtils.destroyCharts();
    }
});

console.log('Analytics JavaScript loaded successfully - sharondelya Network Traffic Analyzer');