FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    tftpd-hpa \
    python3 \
    python3-pip \
    iproute2 \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create TFTP root directory
RUN mkdir -p /var/tftp

# Copy test files
COPY files/ /var/tftp

# Set permissions
RUN chmod -R 755 /var/tftp && \
    chown -R nobody:nogroup /var/tftp

# Copy the TFTP client script
COPY tftp_client_docker.py /usr/local/bin/tftp_client.py
RUN chmod +x /usr/local/bin/tftp_client.py

# Expose ports
# Port 69 is the TFTP control port
# Ports 1024-1027 are the data transfer ports (as per MC2_tftp.tla)
# Port 5000 is the TCP control port for the client
#EXPOSE 69 1024-1027 5000

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Docker Compose already assigns the IP via ipv4_address, no manual configuration needed\n\
\n\
# Start TFTP server in background\n\
in.tftpd -L --foreground --address ${SERVER_IP}:69 \\\n\
  --user nobody --port-range ${PORT_RANGE} \\\n\
  --secure /var/tftp &\n\
\n\
TFTPD_PID=$!\n\
echo "TFTP server started with PID $TFTPD_PID"\n\
\n\
# Start client control server if CLIENT_IP is set\n\
if [ -n "${CLIENT_IP}" ]; then\n\
  echo "Starting TFTP client control server on ${CLIENT_IP}:${CONTROL_PORT:-15000}"\n\
  python3 /usr/local/bin/tftp_client.py \\\n\
    --client-ip ${CLIENT_IP} \\\n\
    --server-ip ${SERVER_IP} \\\n\
    --control-port ${CONTROL_PORT:-15000} &\n\
  CLIENT_PID=$!\n\
  echo "Client started with PID $CLIENT_PID"\n\
fi\n\
\n\
# Wait for processes\n\
wait\n\
' > /usr/local/bin/start.sh && chmod +x /usr/local/bin/start.sh

CMD ["/usr/local/bin/start.sh"]