#!/bin/bash

# Service management script for python-validity and open-fprintd coordination
# This script helps manage the two services to avoid USB device conflicts

set -e

PYTHON_VALIDITY_SERVICE="python3-validity.service"
OPEN_FPRINTD_SERVICE="open-fprintd.service"

show_usage() {
    echo "Usage: $0 {start|stop|restart|status|switch-to-validity|switch-to-fprintd}"
    echo ""
    echo "Commands:"
    echo "  start              - Start both services (python-validity first)"
    echo "  stop               - Stop both services"
    echo "  restart            - Restart both services"
    echo "  status             - Show status of both services"
    echo "  switch-to-validity - Stop open-fprintd and start python-validity"
    echo "  switch-to-fprintd  - Stop python-validity and start open-fprintd"
    echo ""
    echo "This script helps coordinate the two fingerprint services to avoid"
    echo "USB device access conflicts."
}

check_service_status() {
    local service=$1
    if systemctl is-active --quiet "$service"; then
        echo "running"
    else
        echo "stopped"
    fi
}

wait_for_service_stop() {
    local service=$1
    local timeout=10
    local count=0
    
    while systemctl is-active --quiet "$service" && [ $count -lt $timeout ]; do
        sleep 1
        count=$((count + 1))
    done
    
    if [ $count -eq $timeout ]; then
        echo "Warning: $service did not stop within $timeout seconds"
        return 1
    fi
    return 0
}

case "$1" in
    start)
        echo "Starting fingerprint services..."
        
        # Start open-fprintd first (it's the manager)
        echo "Starting $OPEN_FPRINTD_SERVICE..."
        systemctl start "$OPEN_FPRINTD_SERVICE"
        sleep 2
        
        # Then start python-validity
        echo "Starting $PYTHON_VALIDITY_SERVICE..."
        systemctl start "$PYTHON_VALIDITY_SERVICE"
        
        echo "Services started."
        ;;
        
    stop)
        echo "Stopping fingerprint services..."
        
        # Stop python-validity first
        if systemctl is-active --quiet "$PYTHON_VALIDITY_SERVICE"; then
            echo "Stopping $PYTHON_VALIDITY_SERVICE..."
            systemctl stop "$PYTHON_VALIDITY_SERVICE"
            wait_for_service_stop "$PYTHON_VALIDITY_SERVICE"
        fi
        
        # Then stop open-fprintd
        if systemctl is-active --quiet "$OPEN_FPRINTD_SERVICE"; then
            echo "Stopping $OPEN_FPRINTD_SERVICE..."
            systemctl stop "$OPEN_FPRINTD_SERVICE"
            wait_for_service_stop "$OPEN_FPRINTD_SERVICE"
        fi
        
        echo "Services stopped."
        ;;
        
    restart)
        echo "Restarting fingerprint services..."
        $0 stop
        sleep 2
        $0 start
        ;;
        
    status)
        echo "Fingerprint services status:"
        echo "  $OPEN_FPRINTD_SERVICE: $(check_service_status "$OPEN_FPRINTD_SERVICE")"
        echo "  $PYTHON_VALIDITY_SERVICE: $(check_service_status "$PYTHON_VALIDITY_SERVICE")"
        
        # Show recent logs if there are failures
        if ! systemctl is-active --quiet "$PYTHON_VALIDITY_SERVICE"; then
            echo ""
            echo "Recent $PYTHON_VALIDITY_SERVICE logs:"
            journalctl -u "$PYTHON_VALIDITY_SERVICE" --no-pager -n 5 --since "5 minutes ago" || true
        fi
        ;;
        
    switch-to-validity)
        echo "Switching to python-validity service..."
        
        if systemctl is-active --quiet "$OPEN_FPRINTD_SERVICE"; then
            echo "Stopping $OPEN_FPRINTD_SERVICE..."
            systemctl stop "$OPEN_FPRINTD_SERVICE"
            wait_for_service_stop "$OPEN_FPRINTD_SERVICE"
        fi
        
        sleep 1
        
        echo "Starting $PYTHON_VALIDITY_SERVICE..."
        systemctl start "$PYTHON_VALIDITY_SERVICE"
        
        echo "Switched to python-validity."
        ;;
        
    switch-to-fprintd)
        echo "Switching to open-fprintd service..."
        
        if systemctl is-active --quiet "$PYTHON_VALIDITY_SERVICE"; then
            echo "Stopping $PYTHON_VALIDITY_SERVICE..."
            systemctl stop "$PYTHON_VALIDITY_SERVICE"
            wait_for_service_stop "$PYTHON_VALIDITY_SERVICE"
        fi
        
        sleep 1
        
        echo "Starting $OPEN_FPRINTD_SERVICE..."
        systemctl start "$OPEN_FPRINTD_SERVICE"
        
        echo "Switched to open-fprintd."
        ;;
        
    *)
        show_usage
        exit 1
        ;;
esac

exit 0
