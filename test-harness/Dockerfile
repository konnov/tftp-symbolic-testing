FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    tftpd-hpa \
    python3 \
    python3-pip \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    coreutils \
    rsyslog \
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
# Watchdog function to monitor TFTP server\n\
run_tftpd_with_watchdog() {\n\
  local restart_count=0\n\
  local max_restarts=1\n\
  \n\
  # Configure rsyslog to capture tftp messages\n\
  # Create a rule to log daemon facility messages (which tftp uses) to a dedicated file\n\
  mkdir -p /etc/rsyslog.d\n\
  echo "daemon.* /var/log/tftp_syslog.log" > /etc/rsyslog.d/50-tftp.conf\n\
  \n\
  # Create the log file and set permissions\n\
  touch /var/log/tftp_syslog.log\n\
  chmod 644 /var/log/tftp_syslog.log\n\
  \n\
  # Start rsyslog to capture syslog messages\n\
  rsyslogd\n\
  echo "Started rsyslog daemon (tftp logs will be in /var/log/tftp_syslog.log)"\n\
  \n\
  while [ $restart_count -lt $max_restarts ]; do\n\
    echo "Starting TFTP server (attempt $((restart_count + 1))/$max_restarts)"\n\
    echo "Command: in.tftpd -vvv --foreground --address ${SERVER_IP}:69 --user nobody --port-range ${PORT_RANGE} --secure /var/tftp"\n\
    \n\
    # Start tcpdump in background to capture TFTP traffic\n\
    # -l: Line buffered output (immediate output per line)\n\
    # -U: Packet buffered output (don't wait for buffer to fill)\n\
    # -i any: Capture on all interfaces\n\
    # -n: Don't resolve addresses\n\
    # -s 0: Capture full packets\n\
    # -vv: Very verbose\n\
    # -w: Write raw packets to pcap file for later analysis\n\
    tcpdump -i any -n -s 0 -w /var/log/tftp.pcap udp 2>&1 | stdbuf -oL -eL tee /dev/stderr &\n\
    TCPDUMP_PID=$!\n\
    echo "Started tcpdump with PID $TCPDUMP_PID (saving to /var/log/tftp.pcap)"\n\
    \n\
    # Start TFTP server in foreground with verbose logging\n\
    # Using stdbuf to disable buffering so we see output immediately\n\
    # Redirect both stdout and stderr to ensure we capture everything\n\
    # -vv: Verbose logging (warnings and debug messages)\n\
    exec 2>&1\n\
    stdbuf -oL -eL in.tftpd -vvvv --foreground --address ${SERVER_IP}:69 \\\n\
      --user nobody --port-range ${PORT_RANGE} \\\n\
      --secure /var/tftp\n\
    \n\
    exit_code=$?\n\
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")\n\
    \n\
    if [ $exit_code -eq 0 ]; then\n\
      echo "[$timestamp] TFTP server exited normally with code 0"\n\
      break\n\
    else\n\
      echo "[$timestamp] !!! TFTP SERVER CRASHED !!!"\n\
      echo "[$timestamp] Exit code: $exit_code"\n\
      echo "[$timestamp] Signal: $((exit_code - 128))"\n\
      restart_count=$((restart_count + 1))\n\
      \n\
      if [ $restart_count -lt $max_restarts ]; then\n\
        echo "[$timestamp] Restarting TFTP server in 2 seconds..."\n\
        sleep 2\n\
      else\n\
        echo "[$timestamp] Maximum restart attempts reached. Giving up."\n\
        return $exit_code\n\
      fi\n\
    fi\n\
  done\n\
}\n\
\n\
# Start TFTP server with watchdog in background\n\
run_tftpd_with_watchdog &\n\
TFTPD_PID=$!\n\
echo "TFTP server watchdog started with PID $TFTPD_PID"\n\
\n\
# Start client control server if CLIENT_IP is set\n\
if [ -n "${CLIENT_IP}" ]; then\n\
  echo "Starting TFTP client control server on ${CLIENT_IP}:${CONTROL_PORT:-15000}"\n\
  \n\
  # Start tcpdump for client traffic capture\n\
  tcpdump -i any -n -s 0 -w /var/log/tftp_client.pcap udp 2>&1 | stdbuf -oL -eL tee /dev/stderr &\n\
  TCPDUMP_CLIENT_PID=$!\n\
  echo "Started client tcpdump with PID $TCPDUMP_CLIENT_PID (saving to /var/log/tftp_client.pcap)"\n\
  \n\
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