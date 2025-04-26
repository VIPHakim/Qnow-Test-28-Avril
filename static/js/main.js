document.addEventListener('DOMContentLoaded', function() {
    const responseDisplay = document.getElementById('responseDisplay');

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
        
        // Build the device object
        const device = {};
        const phoneNumber = document.getElementById('phone_number').value;
        const networkAccessId = document.getElementById('network_access_identifier').value;
        const deviceIpv4 = document.getElementById('device_ipv4_address').value;
        const deviceIpv4Port = document.getElementById('device_ipv4_port').value;
        const deviceIpv6 = document.getElementById('device_ipv6_address').value;

        if (phoneNumber) {
            device.phoneNumber = phoneNumber;
        }
        if (networkAccessId) {
            device.networkAccessIdentifier = networkAccessId;
        }
        if (deviceIpv4) {
            device.ipv4Address = {
                publicAddress: deviceIpv4
            };
            if (deviceIpv4Port) {
                device.ipv4Address.publicPort = parseInt(deviceIpv4Port);
            }
        }
        if (deviceIpv6) {
            device.ipv6Address = deviceIpv6;
        }

        // Build the application server object
        const applicationServer = {};
        const serverIpv4 = document.getElementById('server_ipv4_address').value;
        const serverIpv6 = document.getElementById('server_ipv6_address').value;

        if (serverIpv4 && isValidIpv4(serverIpv4)) {
            applicationServer.ipv4Address = serverIpv4;
        }
        if (serverIpv6 && isValidIpv6(serverIpv6)) {
            applicationServer.ipv6Address = serverIpv6;
        }

        // Build the request payload
        const formData = {
            duration: parseInt(document.getElementById('duration').value) || 86400,
            device: device,
            applicationServer: applicationServer,
            qosProfile: document.getElementById('qos_profile').value
        };

        // Add device ports if specified
        const devicePortRangeFrom = document.getElementById('device_port_range_from').value;
        const devicePortRangeTo = document.getElementById('device_port_range_to').value;
        const devicePorts = parsePorts(document.getElementById('device_ports').value);

        if (devicePortRangeFrom && devicePortRangeTo || devicePorts.length > 0) {
            formData.devicePorts = {};
            if (devicePortRangeFrom && devicePortRangeTo) {
                formData.devicePorts.ranges = [{
                    from: parseInt(devicePortRangeFrom),
                    to: parseInt(devicePortRangeTo)
                }];
            }
            if (devicePorts.length > 0) {
                formData.devicePorts.ports = devicePorts;
            }
        }

        // Add application server ports if specified
        const serverPortRangeFrom = document.getElementById('server_port_range_from').value;
        const serverPortRangeTo = document.getElementById('server_port_range_to').value;
        const serverPorts = parsePorts(document.getElementById('server_ports').value);

        if (serverPortRangeFrom && serverPortRangeTo || serverPorts.length > 0) {
            formData.applicationServerPorts = {};
            if (serverPortRangeFrom && serverPortRangeTo) {
                formData.applicationServerPorts.ranges = [{
                    from: parseInt(serverPortRangeFrom),
                    to: parseInt(serverPortRangeTo)
                }];
            }
            if (serverPorts.length > 0) {
                formData.applicationServerPorts.ports = serverPorts;
            }
        }

        // Add webhook information if provided
        const notificationUrl = document.getElementById('notification_url').value;
        const notificationAuthToken = document.getElementById('notification_auth_token').value;
        
        if (notificationUrl) {
            formData.webhook = {
                notificationUrl: notificationUrl
            };
            if (notificationAuthToken && notificationAuthToken.length >= 20) {
                formData.webhook.notificationAuthToken = notificationAuthToken;
            }
        }

        try {
            // Validate required fields
            if (!formData.device || Object.keys(formData.device).length === 0) {
                throw new Error('At least one device identifier is required');
            }
            if (!formData.applicationServer || Object.keys(formData.applicationServer).length === 0) {
                throw new Error('At least one application server address is required');
            }
            if (!formData.qosProfile) {
                throw new Error('QoS Profile is required');
            }

            const response = await fetch('/qos/request', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });

            const data = await response.json();
            if (response.ok) {
                displayResponse(data);
            } else {
                handleError(new Error(data.message || 'Failed to create session'));
            }
        } catch (error) {
            handleError(error);
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