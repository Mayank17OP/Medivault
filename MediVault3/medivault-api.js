// MediVault API Integration
class MediVaultAPI {
    constructor() {
        this.baseURL = '/api';
        this.currentUser = this.getCurrentUser();
    }

    // Authentication methods
    async register(userData) {
        try {
            const response = await fetch(`${this.baseURL}/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });
            const data = await response.json();
            
            if (response.ok) {
                this.setCurrentUser(data);
                return { success: true, data };
            } else {
                return { success: false, error: data.error };
            }
        } catch (error) {
            return { success: false, error: 'Network error' };
        }
    }

    async login(email, password, accountType) {
        try {
            const response = await fetch(`${this.baseURL}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, account_type: accountType })
            });
            const data = await response.json();
            
            if (response.ok) {
                this.setCurrentUser(data.user);
                return { success: true, user: data.user };
            } else {
                return { success: false, error: data.error };
            }
        } catch (error) {
            return { success: false, error: 'Network error' };
        }
    }

    logout() {
        localStorage.removeItem('medivault_user');
        this.currentUser = null;
        window.location.href = '/index.html';
    }

    // File management methods
    async uploadFile(file, metadata, userId) {
        try {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('user_id', userId);
            formData.append('description', metadata.description || '');
            formData.append('category', metadata.category || 'general');
            formData.append('doctor_name', metadata.doctor_name || '');
            formData.append('hospital_name', metadata.hospital_name || '');

            const response = await fetch(`${this.baseURL}/files/upload`, {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            
            return response.ok ? { success: true, data } : { success: false, error: data.error };
        } catch (error) {
            return { success: false, error: 'Upload failed' };
        }
    }

    async getFiles(userId) {
        try {
            const response = await fetch(`${this.baseURL}/files/${userId}`);
            const data = await response.json();
            
            return response.ok ? { success: true, files: data.files } : { success: false, error: data.error };
        } catch (error) {
            return { success: false, error: 'Failed to fetch files' };
        }
    }

    getDownloadUrl(fileId) {
        return `${this.baseURL}/files/download/${fileId}`;
    }

    // Emergency profile methods
    async getEmergencyProfile(userId) {
        try {
            const response = await fetch(`${this.baseURL}/emergency-profile/${userId}`);
            const data = await response.json();
            
            return response.ok ? { success: true, data } : { success: false, error: data.error };
        } catch (error) {
            return { success: false, error: 'Failed to fetch profile' };
        }
    }

    async updateEmergencyProfile(userId, profileData) {
        try {
            const response = await fetch(`${this.baseURL}/emergency-profile/${userId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(profileData)
            });
            const data = await response.json();
            
            return response.ok ? { success: true, data } : { success: false, error: data.error };
        } catch (error) {
            return { success: false, error: 'Failed to update profile' };
        }
    }

    // QR code methods
    async generateQR(userId, accessType = 'emergency') {
        try {
            const response = await fetch(`${this.baseURL}/qr/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, access_type: accessType })
            });
            const data = await response.json();
            
            return response.ok ? { success: true, data } : { success: false, error: data.error };
        } catch (error) {
            return { success: false, error: 'Failed to generate QR code' };
        }
    }

    async accessQR(token) {
        try {
            const response = await fetch(`${this.baseURL}/qr/access/${token}`);
            const data = await response.json();
            
            return response.ok ? { success: true, data } : { success: false, error: data.error };
        } catch (error) {
            return { success: false, error: 'Failed to access QR code' };
        }
    }

    // Dashboard methods
    async getDashboardStats(userId) {
        try {
            const response = await fetch(`${this.baseURL}/dashboard/stats/${userId}`);
            const data = await response.json();
            
            return response.ok ? { success: true, data } : { success: false, error: data.error };
        } catch (error) {
            return { success: false, error: 'Failed to fetch dashboard stats' };
        }
    }

    // Health check
    async healthCheck() {
        try {
            const response = await fetch(`${this.baseURL}/health`);
            const data = await response.json();
            
            return response.ok ? { success: true, data } : { success: false, error: data.error };
        } catch (error) {
            return { success: false, error: 'Health check failed' };
        }
    }

    // User management
    setCurrentUser(user) {
        this.currentUser = user;
        localStorage.setItem('medivault_user', JSON.stringify(user));
    }

    getCurrentUser() {
        const stored = localStorage.getItem('medivault_user');
        return stored ? JSON.parse(stored) : null;
    }

    isLoggedIn() {
        return this.currentUser !== null;
    }

    requireAuth() {
        if (!this.isLoggedIn()) {
            window.location.href = '/login.html';
            return false;
        }
        return true;
    }

    // Utility methods
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type} fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 max-w-sm`;
        notification.style.cssText = `
            background-color: ${type === 'success' ? '#10B981' : type === 'error' ? '#EF4444' : '#3B82F6'};
            color: white;
            transform: translateX(100%);
            transition: transform 0.3s ease;
        `;
        notification.textContent = message;

        document.body.appendChild(notification);

        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);

        // Auto remove after 5 seconds
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 5000);
    }

    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

// Initialize API
const medivaultAPI = new MediVaultAPI();

// Global authentication check for protected pages
document.addEventListener('DOMContentLoaded', function() {
    const protectedPages = ['dashboard.html', 'doctorsdashboard.html', 'qrcode.html', 'emergency.html'];
    const currentPage = window.location.pathname.split('/').pop();
    
    if (protectedPages.includes(currentPage)) {
        if (!medivaultAPI.requireAuth()) {
            return;
        }
        
        // Load user-specific content
        loadUserContent();
    }
});

// Load user-specific content for protected pages
async function loadUserContent() {
    const user = medivaultAPI.getCurrentUser();
    if (!user) return;

    const currentPage = window.location.pathname.split('/').pop();
    
    switch (currentPage) {
        case 'dashboard.html':
            await loadDashboardContent(user);
            break;
        case 'doctorsdashboard.html':
            await loadDoctorDashboardContent(user);
            break;
        case 'qrcode.html':
            await loadQRContent(user);
            break;
        case 'emergency.html':
            await loadEmergencyContent(user);
            break;
    }
}

// Dashboard content loader
async function loadDashboardContent(user) {
    try {
        // Update user name
        const nameElements = document.querySelectorAll('[data-user-name]');
        nameElements.forEach(el => el.textContent = user.full_name);

        // Load dashboard stats
        const statsResult = await medivaultAPI.getDashboardStats(user.id);
        if (statsResult.success) {
            updateDashboardStats(statsResult.data);
        }

        // Load recent files
        const filesResult = await medivaultAPI.getFiles(user.id);
        if (filesResult.success) {
            updateFilesList(filesResult.files);
        }

        // Load emergency profile
        const profileResult = await medivaultAPI.getEmergencyProfile(user.id);
        if (profileResult.success && profileResult.data.profile) {
            updateEmergencyInfo(profileResult.data.profile);
        }

    } catch (error) {
        console.error('Failed to load dashboard content:', error);
        medivaultAPI.showNotification('Failed to load dashboard data', 'error');
    }
}

// Update dashboard statistics
function updateDashboardStats(stats) {
    const totalFilesEl = document.querySelector('[data-total-files]');
    if (totalFilesEl) totalFilesEl.textContent = stats.total_files || 0;

    const recentActivityEl = document.querySelector('[data-recent-activity]');
    if (recentActivityEl && stats.recent_activity) {
        recentActivityEl.innerHTML = stats.recent_activity
            .slice(0, 5)
            .map(activity => `
                <div class="activity-item p-2 border-b">
                    <span class="font-medium">${activity.action}</span>
                    <span class="text-sm text-gray-500">${medivaultAPI.formatDate(activity.timestamp)}</span>
                </div>
            `).join('');
    }
}

// Update files list
function updateFilesList(files) {
    const filesContainer = document.querySelector('[data-files-list]');
    if (!filesContainer) return;

    if (files.length === 0) {
        filesContainer.innerHTML = '<p class="text-gray-500">No files uploaded yet.</p>';
        return;
    }

    filesContainer.innerHTML = files.slice(0, 10).map(file => `
        <div class="file-item p-4 border border-gray-200 rounded-lg mb-3">
            <div class="flex justify-between items-start">
                <div>
                    <h4 class="font-medium text-gray-900">${file.original_filename}</h4>
                    <p class="text-sm text-gray-600">${file.description || 'No description'}</p>
                    <div class="flex space-x-4 text-xs text-gray-500 mt-1">
                        <span>Size: ${medivaultAPI.formatFileSize(file.file_size)}</span>
                        <span>Uploaded: ${medivaultAPI.formatDate(file.upload_date)}</span>
                        ${file.doctor_name ? `<span>Dr: ${file.doctor_name}</span>` : ''}
                    </div>
                </div>
                <div class="flex space-x-2">
                    <a href="${medivaultAPI.getDownloadUrl(file.id)}" 
                       class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                        Download
                    </a>
                </div>
            </div>
        </div>
    `).join('');
}

// QR code content loader
async function loadQRContent(user) {
    try {
        // Update user info
        const userNameEl = document.querySelector('[data-qr-user-name]');
        if (userNameEl) userNameEl.textContent = user.full_name;

        const userIdEl = document.querySelector('[data-qr-user-id]');
        if (userIdEl) userIdEl.textContent = `MV-${user.id.toString().padStart(6, '0')}`;

        // Generate QR code on button click
        const generateBtn = document.querySelector('[data-generate-qr]');
        if (generateBtn) {
            generateBtn.addEventListener('click', async () => {
                const result = await medivaultAPI.generateQR(user.id);
                if (result.success) {
                    displayQRCode(result.data);
                } else {
                    medivaultAPI.showNotification('Failed to generate QR code', 'error');
                }
            });
        }

    } catch (error) {
        console.error('Failed to load QR content:', error);
    }
}

// Display generated QR code
function displayQRCode(qrData) {
    const qrContainer = document.querySelector('[data-qr-display]');
    if (qrContainer) {
        qrContainer.innerHTML = `
            <div class="text-center">
                <img src="${qrData.qr_image}" alt="QR Code" class="mx-auto mb-4" />
                <p class="text-sm text-gray-600">QR Code expires: ${medivaultAPI.formatDate(qrData.expires_at)}</p>
                <button onclick="downloadQRCode('${qrData.qr_image}')" 
                        class="mt-4 bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                    Download QR Code
                </button>
            </div>
        `;
    }
}

// Download QR code function
function downloadQRCode(base64Image) {
    const link = document.createElement('a');
    link.href = base64Image;
    link.download = `medivault-qr-${Date.now()}.png`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    medivaultAPI.showNotification('QR code downloaded successfully', 'success');
}

// Emergency profile content loader
async function loadEmergencyContent(user) {
    try {
        const result = await medivaultAPI.getEmergencyProfile(user.id);
        if (result.success) {
            displayEmergencyProfile(result.data.user, result.data.profile);
        }
    } catch (error) {
        console.error('Failed to load emergency content:', error);
    }
}

// Display emergency profile
function displayEmergencyProfile(user, profile) {
    // Update user name
    const nameEl = document.querySelector('[data-emergency-name]');
    if (nameEl) nameEl.textContent = user.full_name;

    // Update profile fields
    const fields = [
        'blood_type', 'allergies', 'medical_conditions', 'current_medications',
        'emergency_contact_name', 'emergency_contact_phone',
        'secondary_contact_name', 'secondary_contact_phone',
        'primary_doctor_name', 'primary_doctor_phone', 'primary_doctor_hospital'
    ];

    fields.forEach(field => {
        const el = document.querySelector(`[data-emergency-${field.replace('_', '-')}]`);
        if (el && profile[field]) {
            el.textContent = profile[field];
        }
    });

    // Update organ donor status
    const organDonorEl = document.querySelector('[data-organ-donor]');
    if (organDonorEl) {
        organDonorEl.textContent = profile.organ_donor ? 'Registered Organ Donor' : 'Not an organ donor';
    }
}

// Export for use in HTML files
window.medivaultAPI = medivaultAPI;