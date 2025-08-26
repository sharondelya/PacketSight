/**
 * Real-time Activity Feed for PacketSight Dashboard
 * Author: sharondelya
 * Description: Handles real-time network activity display with filtering
 */

function loadRecentActivity(filter = 'all') {
    const activityFeed = document.getElementById('activityFeed');
    if (!activityFeed) return;

    // Show loading state
    activityFeed.innerHTML = `
        <div class="text-center py-3">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="text-muted mt-2">Loading recent activity...</p>
        </div>
    `;

    // Fetch real-time activity data
    fetch(`/api/recent-activity?filter=${filter}&limit=15`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(activities => {
            if (!activities || activities.length === 0) {
                activityFeed.innerHTML = `
                    <div class="text-center py-4">
                        <i class="fas fa-inbox text-muted fa-2x mb-3"></i>
                        <p class="text-muted mb-0">No recent network activity found</p>
                        <button class="btn btn-primary btn-sm mt-2" onclick="simulateTraffic()">
                            Generate Sample Traffic
                        </button>
                    </div>
                `;
                return;
            }

            // Build activity HTML from real data
            let activityHTML = '';
            activities.forEach(activity => {
                activityHTML += `
                    <div class="activity-item" data-type="${activity.type}">
                        <div class="activity-icon bg-${activity.color}">
                            <i class="${activity.icon}"></i>
                        </div>
                        <div class="activity-content">
                            <div class="activity-title">${activity.title}</div>
                            <div class="activity-details">${activity.details}</div>
                            <div class="activity-time">${activity.time_ago}</div>
                        </div>
                    </div>
                `;
            });

            activityFeed.innerHTML = activityHTML;
            
            // Setup filter event listeners
            setupActivityFilters();
        })
        .catch(error => {
            console.error('Error loading recent activity:', error);
            activityFeed.innerHTML = `
                <div class="text-center py-4">
                    <i class="fas fa-exclamation-triangle text-warning fa-2x mb-3"></i>
                    <p class="text-muted mb-0">Failed to load recent activity</p>
                    <button class="btn btn-outline-primary btn-sm mt-2" onclick="loadRecentActivity()">
                        Try Again
                    </button>
                </div>
            `;
        });
}

function setupActivityFilters() {
    // Setup filter button event listeners
    document.querySelectorAll('.activity-filters .btn').forEach(btn => {
        btn.addEventListener('click', function() {
            // Remove active class from all buttons
            document.querySelectorAll('.activity-filters .btn').forEach(b => 
                b.classList.remove('active'));
            
            // Add active class to clicked button
            this.classList.add('active');
            
            // Get filter value
            const filter = this.dataset.filter || this.textContent.toLowerCase();
            
            // Apply filter
            filterActivityFeed(filter);
        });
    });
}

function filterActivityFeed(filter) {
    if (filter === 'all') {
        // Reload all activities
        loadRecentActivity('all');
    } else {
        // Load filtered activities
        loadRecentActivity(filter);
    }
}

// Auto-refresh activity feed every 30 seconds
setInterval(function() {
    const activeFilter = document.querySelector('.activity-filters .btn.active');
    const filter = activeFilter ? (activeFilter.dataset.filter || activeFilter.textContent.toLowerCase()) : 'all';
    loadRecentActivity(filter);
}, 30000);