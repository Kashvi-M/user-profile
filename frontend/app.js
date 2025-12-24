// API Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// State management
let authToken = localStorage.getItem('authToken');

// DOM Elements
const loginContainer = document.getElementById('loginContainer');
const registerContainer = document.getElementById('registerContainer');
const dashboardContainer = document.getElementById('dashboardContainer');
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const showRegisterLink = document.getElementById('showRegister');
const showLoginLink = document.getElementById('showLogin');
const logoutBtn = document.getElementById('logoutBtn');

// Check if user is already logged in
if (authToken) {
    showDashboard();
    fetchProfile();
} else {
    showLogin();
}

// Event Listeners
showRegisterLink.addEventListener('click', (e) => {
    e.preventDefault();
    showRegister();
});

showLoginLink.addEventListener('click', (e) => {
    e.preventDefault();
    showLogin();
});

logoutBtn.addEventListener('click', () => {
    logout();
});

// Update Aadhaar/ID event listeners
const showUpdateFormBtn = document.getElementById('showUpdateFormBtn');
const updateAadhaarBtn = document.getElementById('updateAadhaarBtn');
const cancelUpdateBtn = document.getElementById('cancelUpdateBtn');
const updateAadhaarForm = document.getElementById('updateAadhaarForm');
const updateAadhaarInput = document.getElementById('updateAadhaarInput');

if (showUpdateFormBtn) {
    showUpdateFormBtn.addEventListener('click', () => {
        updateAadhaarForm.style.display = 'block';
        showUpdateFormBtn.style.display = 'none';
    });
}

if (cancelUpdateBtn) {
    cancelUpdateBtn.addEventListener('click', () => {
        updateAadhaarForm.style.display = 'none';
        updateAadhaarInput.value = '';
        if (document.querySelector('.warning-message')) {
            showUpdateFormBtn.style.display = 'inline-block';
        }
    });
}

if (updateAadhaarBtn) {
    updateAadhaarBtn.addEventListener('click', async () => {
        await updateAadhaarId();
    });
}

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    await handleLogin();
});

registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    await handleRegister();
});

// UI Functions
function showLogin() {
    loginContainer.style.display = 'flex';
    registerContainer.style.display = 'none';
    dashboardContainer.style.display = 'none';
    clearErrors();
}

function showRegister() {
    loginContainer.style.display = 'none';
    registerContainer.style.display = 'flex';
    dashboardContainer.style.display = 'none';
    clearErrors();
}

function showDashboard() {
    loginContainer.style.display = 'none';
    registerContainer.style.display = 'none';
    dashboardContainer.style.display = 'block';
}

function clearErrors() {
    document.getElementById('loginError').style.display = 'none';
    document.getElementById('registerError').style.display = 'none';
    document.getElementById('profileError').style.display = 'none';
}

function showError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    errorElement.textContent = message;
    errorElement.style.display = 'block';
}

// API Functions
async function apiRequest(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
    };

    // Always check localStorage for the latest token
    const token = localStorage.getItem('authToken') || authToken;
    if (token) {
        defaultOptions.headers['Authorization'] = `Bearer ${token}`;
    }

    const config = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers,
        },
    };

    try {
        const response = await fetch(url, config);
        const data = await response.json();

        if (!response.ok) {
            const errorMsg = data.error || data.message || `HTTP error! status: ${response.status}`;
            console.error('API Error:', {
                status: response.status,
                error: errorMsg,
                url: url,
                hasToken: !!authToken
            });
            throw new Error(errorMsg);
        }

        return data;
    } catch (error) {
        if (error instanceof TypeError && error.message.includes('fetch')) {
            throw new Error('Network error: Could not connect to server');
        }
        throw error;
    }
}

// Authentication Functions
async function handleLogin() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    try {
        clearErrors();
        const data = await apiRequest('/login', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
        });

        authToken = data.access_token;
        localStorage.setItem('authToken', authToken);
        showDashboard();
        // Small delay to ensure token is set before fetching profile
        await new Promise(resolve => setTimeout(resolve, 100));
        await fetchProfile();
    } catch (error) {
        showError('loginError', error.message || 'Login failed. Please check your credentials.');
    }
}

async function handleRegister() {
    const formData = {
        email: document.getElementById('registerEmail').value,
        password: document.getElementById('registerPassword').value,
        full_name: document.getElementById('fullName').value || undefined,
        phone: document.getElementById('phone').value || undefined,
        aadhaar_id: document.getElementById('aadhaarId').value || undefined,
        date_of_birth: document.getElementById('dateOfBirth').value || undefined,
        address: document.getElementById('address').value || undefined,
    };

    try {
        clearErrors();
        const data = await apiRequest('/register', {
            method: 'POST',
            body: JSON.stringify(formData),
        });

        authToken = data.access_token;
        localStorage.setItem('authToken', authToken);
        showDashboard();
        // Small delay to ensure token is set before fetching profile
        await new Promise(resolve => setTimeout(resolve, 100));
        await fetchProfile();
    } catch (error) {
        showError('registerError', error.message || 'Registration failed. Please try again.');
    }
}

async function fetchProfile() {
    const loadingMessage = document.getElementById('loadingMessage');
    const profileContent = document.getElementById('profileContent');
    const profileError = document.getElementById('profileError');

    try {
        loadingMessage.style.display = 'block';
        profileContent.style.display = 'none';
        profileError.style.display = 'none';

        const data = await apiRequest('/profile');

        // Show decryption warning if present
        if (data.decryption_warning) {
            const warningElement = document.createElement('div');
            warningElement.className = 'warning-message';
            warningElement.style.cssText = 'background-color: #fff3cd; border: 1px solid #ffc107; color: #856404; padding: 12px; border-radius: 4px; margin-bottom: 16px;';
            warningElement.innerHTML = '⚠ ' + data.decryption_warning + '<br><small>You can update your Aadhaar/ID below to re-encrypt it with the current key.</small>';
            const profileCard = document.querySelector('.profile-card');
            if (profileCard) {
                profileCard.insertBefore(warningElement, profileCard.firstChild);
            }
            // Show update button
            document.getElementById('showUpdateFormBtn').style.display = 'inline-block';
        } else {
            document.getElementById('showUpdateFormBtn').style.display = 'none';
        }

        // Populate profile data
        document.getElementById('profileEmail').textContent = data.email || 'N/A';
        document.getElementById('profileFullName').textContent = data.full_name || 'N/A';
        document.getElementById('profilePhone').textContent = data.phone || 'N/A';
        document.getElementById('profileAddress').textContent = data.address || 'N/A';
        document.getElementById('profileAadhaar').textContent = data.aadhaar_id || 'N/A';
        document.getElementById('profileDOB').textContent = data.date_of_birth || 'N/A';
        
        if (data.created_at) {
            const date = new Date(data.created_at);
            document.getElementById('profileCreatedAt').textContent = date.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'long',
                day: 'numeric'
            });
        } else {
            document.getElementById('profileCreatedAt').textContent = 'N/A';
        }

        loadingMessage.style.display = 'none';
        profileContent.style.display = 'block';
    } catch (error) {
        loadingMessage.style.display = 'none';
        showError('profileError', error.message || 'Failed to load profile. Please try again.');
        
        // If token is invalid, logout
        if (error.message.includes('401') || error.message.includes('Invalid')) {
            setTimeout(() => {
                logout();
            }, 2000);
        }
    }
}

async function updateAadhaarId() {
    const aadhaarId = updateAadhaarInput.value.trim();
    
    if (!aadhaarId) {
        alert('Please enter an Aadhaar/ID number');
        return;
    }
    
    try {
        updateAadhaarBtn.disabled = true;
        updateAadhaarBtn.textContent = 'Updating...';
        
        const data = await apiRequest('/profile', {
            method: 'PUT',
            body: JSON.stringify({ aadhaar_id: aadhaarId }),
        });
        
        // Update the displayed value
        document.getElementById('profileAadhaar').textContent = data.aadhaar_id || 'N/A';
        
        // Hide the form and remove warning
        updateAadhaarForm.style.display = 'none';
        updateAadhaarInput.value = '';
        showUpdateFormBtn.style.display = 'none';
        
        // Remove warning message if it exists
        const warningElement = document.querySelector('.warning-message');
        if (warningElement) {
            warningElement.remove();
        }
        
        alert('Aadhaar/ID updated successfully!');
        
    } catch (error) {
        alert('Failed to update Aadhaar/ID: ' + error.message);
    } finally {
        updateAadhaarBtn.disabled = false;
        updateAadhaarBtn.textContent = 'Update';
    }
}

function logout() {
    authToken = null;
    localStorage.removeItem('authToken');
    showLogin();
    loginForm.reset();
    registerForm.reset();
    clearErrors();
}

