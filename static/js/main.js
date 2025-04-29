document.addEventListener('DOMContentLoaded', function() {
    const responseDisplay = document.getElementById('responseDisplay');

    // Load QoS profiles when the page loads
    async function loadQoSProfiles() {
        try {
            console.log('Starting to load QoS profiles...');
            const response = await fetch('/qos/profiles');
            console.log('Raw response:', response);
            
            const data = await response.json();
            console.log('Parsed profiles data:', data);
            
            const profileSelect = document.getElementById('qos_profile');
            profileSelect.innerHTML = '';
            
            if (!response.ok) {
                console.error('Server returned error:', data);
                profileSelect.innerHTML = `<option value="">Error: ${data.error || 'Failed to load profiles'}</option>`;
                return;
            }
            
            if (data.status === 200 && Array.isArray(data.profiles)) {
                console.log('Processing profiles array:', data.profiles);
                
                // Add default option
                const defaultOption = document.createElement('option');
                defaultOption.value = '';
                defaultOption.text = 'Select a profile';
                profileSelect.appendChild(defaultOption);
                
                // Store profiles data globally
                window.profilesData = {};
                
                if (data.profiles.length === 0) {
                    console.log('No profiles found in response array');
                    profileSelect.innerHTML = '<option value="">No profiles available</option>';
                    return;
                }
                
                // Add profile options
                data.profiles.forEach((profile, index) => {
                    console.log(`Processing profile ${index}:`, profile);
                    if (profile && profile.name && profile.id) {
                        const option = document.createElement('option');
                        option.value = profile.id;
                        option.text = profile.name;
                        profileSelect.appendChild(option);
                        
                        window.profilesData[profile.name] = profile;
                    } else {
                        console.warn('Invalid profile data:', profile);
                    }
                });
                
                console.log('Final profiles data:', window.profilesData);
                
            } else {
                console.error('Invalid response format:', data);
                profileSelect.innerHTML = '<option value="">Error: Invalid response format</option>';
            }
        } catch (error) {
            console.error('Error in loadQoSProfiles:', error);
            const profileSelect = document.getElementById('qos_profile');
            profileSelect.innerHTML = `<option value="">Error: ${error.message}</option>`;
        }
    }

    // Load profiles when page loads
    loadQoSProfiles();

    function displayResponse(response) {
        // Create a container for the response
        const container = document.createElement('div');
        
        // Check if we have a session response
        const sessionInfo = response.response;
        if (sessionInfo && sessionInfo.sessionId) {
            // Create session info card
            const sessionCard = document.createElement('div');
            sessionCard.className = 'card mb-3';
            
            // Card header with session ID
            const cardHeader = document.createElement('div');
            cardHeader.className = 'card-header d-flex justify-content-between align-items-center';
            
            const sessionIdTitle = document.createElement('h5');
            sessionIdTitle.className = 'mb-0';
            sessionIdTitle.textContent = 'Session Information';
            
            const copyButton = document.createElement('button');
            copyButton.className = 'btn btn-sm btn-outline-secondary';
            copyButton.textContent = 'Copy ID';
            copyButton.onclick = () => {
                navigator.clipboard.writeText(sessionInfo.sessionId);
                copyButton.textContent = 'Copied!';
                setTimeout(() => {
                    copyButton.textContent = 'Copy ID';
                }, 2000);
            };
            
            cardHeader.appendChild(sessionIdTitle);
            cardHeader.appendChild(copyButton);
            
            // Card body with session details
            const cardBody = document.createElement('div');
            cardBody.className = 'card-body';
            
            // Session ID
            const sessionIdGroup = document.createElement('div');
            sessionIdGroup.className = 'mb-3';
            sessionIdGroup.innerHTML = `
                <label class="fw-bold">Session ID:</label>
                <code class="d-block">${sessionInfo.sessionId}</code>
            `;
            
            // Status
            const statusGroup = document.createElement('div');
            statusGroup.className = 'mb-3';
            statusGroup.innerHTML = `
                <label class="fw-bold">Status:</label>
                <span class="badge ${getStatusBadgeClass(sessionInfo.qosStatus)}">${sessionInfo.qosStatus}</span>
            `;
            
            // Timestamps
            const timesGroup = document.createElement('div');
            timesGroup.className = 'mb-3';
            timesGroup.innerHTML = `
                <label class="fw-bold">Timeline:</label>
                <div>Started: ${formatTimestamp(sessionInfo.startedAt)}</div>
                <div>Expires: ${formatTimestamp(sessionInfo.expiresAt)}</div>
            `;
            
            // Messages if any
            if (sessionInfo.messages && sessionInfo.messages.length > 0) {
                const messagesGroup = document.createElement('div');
                messagesGroup.className = 'mb-3';
                messagesGroup.innerHTML = `
                    <label class="fw-bold">Messages:</label>
                    ${sessionInfo.messages.map(msg => `
                        <div class="alert alert-${msg.severity.toLowerCase()} py-2 mb-2">
                            ${msg.description}
                        </div>
                    `).join('')}
                `;
                cardBody.appendChild(messagesGroup);
            }
            
            // Add all elements to the card
            cardBody.appendChild(sessionIdGroup);
            cardBody.appendChild(statusGroup);
            cardBody.appendChild(timesGroup);
            
            sessionCard.appendChild(cardHeader);
            sessionCard.appendChild(cardBody);
            container.appendChild(sessionCard);
        }

        // Display the full response
        const responseTitle = document.createElement('h5');
        responseTitle.className = 'mb-2';
        responseTitle.textContent = 'Full Response:';
        container.appendChild(responseTitle);

        const responseCode = document.createElement('pre');
        responseCode.className = 'bg-light p-3 rounded';
        responseCode.textContent = JSON.stringify(response, null, 2);
        container.appendChild(responseCode);

        // Clear and update the display
        responseDisplay.innerHTML = '';
        responseDisplay.appendChild(container);
    }

    // Helper function to get appropriate badge class for status
    function getStatusBadgeClass(status) {
        switch (status) {
            case 'REQUESTED':
                return 'bg-warning';
            case 'AVAILABLE':
                return 'bg-success';
            case 'UNAVAILABLE':
                return 'bg-danger';
            default:
                return 'bg-secondary';
        }
    }

    // Helper function to format Unix timestamp
    function formatTimestamp(timestamp) {
        return new Date(timestamp * 1000).toLocaleString();
    }

    function handleError(error) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger';
        errorDiv.textContent = `Error: ${error.message}`;
        responseDisplay.innerHTML = '';
        responseDisplay.appendChild(errorDiv);
    }

    // Helper function to parse comma-separated ports
    function parsePorts(portsString) {
        if (!portsString) return [];
        return portsString.split(',').map(port => parseInt(port.trim())).filter(port => !isNaN(port));
    }

    // Helper function to validate IPv4 address
    function isValidIpv4(ip) {
        const pattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
        return pattern.test(ip);
    }

    // Helper function to validate IPv6 address
    function isValidIpv6(ip) {
        // Basic IPv6 validation - could be enhanced for more strict validation
        return ip.includes(':');
    }

    // Create QoS Session
    document.getElementById('createSessionForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        try {
            const formData = {
                duration: parseInt(document.getElementById('duration').value),
                device: {
                    ipv4Address: {
                        publicAddress: document.getElementById('device_ip').value
                    }
                },
                applicationServer: {
                    ipv4Address: document.getElementById('server_ip').value || "172.20.120.84"
                },
                devicePorts: {
                    ports: [50984]  // Always use this port
                },
                applicationServerPorts: {
                    ports: [10000]  // Always use this port
                },
                qosProfile: document.getElementById('qos_profile').value
            };

            // Add webhook if provided
            const webhookUrl = document.getElementById('webhook_url').value;
            const webhookToken = document.getElementById('webhook_token').value;
            if (webhookUrl) {
                formData.webhook = {
                    notificationUrl: webhookUrl
                };
                if (webhookToken) {
                    formData.webhook.notificationAuthToken = webhookToken;
                }
            }

            console.log('Sending request with data:', formData);

            const response = await fetch('/qos/request', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            });
            
            const data = await response.json();
            displayResponse(data);
            
            if (response.ok) {
                alert('QoS session created successfully!');
            } else {
                alert('Error creating QoS session: ' + (data.detail?.message || JSON.stringify(data)));
            }
        } catch (error) {
            console.error('Error:', error);
            handleError(error);
            alert('Error creating QoS session: ' + error.message);
        }
    });

    // Get Session Status
    document.getElementById('getSessionForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        try {
            const sessionId = document.getElementById('session_id_get').value;
            const response = await fetch(`/qos/session/${sessionId}`);
            const data = await response.json();
            displayResponse(data);
        } catch (error) {
            handleError(error);
        }
    });

    // Delete Session
    document.getElementById('deleteSessionForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        try {
            const sessionId = document.getElementById('session_id_delete').value;
            const response = await fetch(`/qos/session/${sessionId}`, {
                method: 'DELETE'
            });
            const data = await response.json();
            displayResponse(data);
        } catch (error) {
            handleError(error);
        }
    });
}); 