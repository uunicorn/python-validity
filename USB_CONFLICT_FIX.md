# USB Device Conflict Fix for python-validity and open-fprintd

## Problem Description

The combination of `python-validity` and `open-fprintd` services was getting into a state where `python3-validity` repeatedly exits with error code 1. This was caused by USB device access conflicts when both services tried to access the same fingerprint sensor simultaneously.

### Error Pattern
```
systemd: python3-validity.service: Main process exited, code=exited, status=1/FAILURE
systemd: python3-validity.service: Failed with result 'exit-code'.
systemd: python3-validity.service: Scheduled restart job, restart counter is at 27.
dbus-service: File "/usr/lib/python3.13/site-packages/validitysensor/usb.py", line 104, in cmd
```

## Root Cause

1. **Concurrent USB Access**: Both services attempt to access the same USB fingerprint device
2. **Poor Error Handling**: The original code didn't handle USB busy/access errors gracefully
3. **No Coordination**: No mechanism existed to coordinate device access between services
4. **Restart Loops**: Systemd would restart the failing service, creating an endless cycle

## Solution Overview

The fix implements a multi-layered approach:

### 1. Enhanced USB Error Handling (`validitysensor/usb.py`)

- **Retry Logic**: Added exponential backoff retry mechanism (5 attempts)
- **Device Busy Detection**: Proper handling of `EBUSY`, `EAGAIN`, and device busy conditions
- **New Exception Type**: `DeviceBusyException` for better error categorization
- **Graceful Degradation**: Service exits cleanly when device is persistently busy

### 2. Improved Service Error Handling (`dbus_service/dbus-service`)

- **Graceful Exit**: Service exits with code 0 when device is busy (preventing restart loops)
- **Better Resume Logic**: Enhanced resume method to handle device conflicts
- **Comprehensive Logging**: Better error messages to help with debugging

### 3. Updated Systemd Configuration (`debian/python3-validity.service`)

- **Restart Prevention**: `RestartPreventExitStatus=0` prevents restart on graceful exit
- **Service Coordination**: `Wants=open-fprintd.service` for better coordination
- **Timeout Management**: Proper startup and shutdown timeouts
- **Restart Delay**: 5-second delay between restart attempts if they do occur

### 4. Service Management Script (`scripts/manage-services.sh`)

A helper script to properly coordinate the two services:
- Start/stop both services in correct order
- Switch between services safely
- Monitor service status
- Handle service transitions gracefully

## Files Modified

1. **`validitysensor/usb.py`**
   - Added retry logic with exponential backoff
   - Enhanced error handling for USB device conflicts
   - New `DeviceBusyException` class

2. **`dbus_service/dbus-service`**
   - Graceful handling of device busy conditions
   - Improved Resume method
   - Better error logging

3. **`debian/python3-validity.service`**
   - Updated systemd configuration to prevent restart loops
   - Better service coordination settings

4. **`scripts/manage-services.sh`** (New)
   - Service management helper script

## Usage Instructions

### Using the Management Script

```bash
# Make the script executable (if not already)
chmod +x /home/www/DEV-trunk/python-validity/scripts/manage-services.sh

# Start both services
sudo ./scripts/manage-services.sh start

# Stop both services
sudo ./scripts/manage-services.sh stop

# Restart both services
sudo ./scripts/manage-services.sh restart

# Check service status
sudo ./scripts/manage-services.sh status

# Switch to python-validity only
sudo ./scripts/manage-services.sh switch-to-validity

# Switch to open-fprintd only
sudo ./scripts/manage-services.sh switch-to-fprintd
```

### Manual Service Management

```bash
# Stop both services first
sudo systemctl stop python3-validity.service
sudo systemctl stop open-fprintd.service

# Start services in order
sudo systemctl start open-fprintd.service
sleep 2
sudo systemctl start python3-validity.service

# Check status
sudo systemctl status python3-validity.service
sudo systemctl status open-fprintd.service
```

### Monitoring Logs

```bash
# Monitor python-validity logs
sudo journalctl -u python3-validity.service -f

# Monitor open-fprintd logs
sudo journalctl -u open-fprintd.service -f

# Check recent errors
sudo journalctl -u python3-validity.service --since "10 minutes ago"
```

## How the Fix Works

### 1. USB Command Retry Logic
When a USB command fails due to device busy conditions:
1. The system waits with exponential backoff (0.1s, 0.2s, 0.4s, 0.8s, 1.6s)
2. Retries up to 5 times
3. If still busy after all retries, raises `DeviceBusyException`

### 2. Graceful Service Exit
When the device is persistently busy:
1. Service logs a warning about the busy condition
2. Exits with code 0 (success) instead of 1 (failure)
3. Systemd doesn't restart due to `RestartPreventExitStatus=0`

### 3. Service Coordination
- `open-fprintd` acts as the primary service (manager)
- `python-validity` coordinates with it via `Wants=open-fprintd.service`
- Both services can coexist when device access is properly coordinated

## Testing the Fix

1. **Install the updated files**:
   ```bash
   # Copy the modified files to their proper locations
   sudo cp dbus_service/dbus-service /usr/lib/python-validity/
   sudo cp debian/python3-validity.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

2. **Test the fix**:
   ```bash
   # Stop both services
   sudo ./scripts/manage-services.sh stop
   
   # Start both services
   sudo ./scripts/manage-services.sh start
   
   # Monitor for restart loops (should not occur)
   sudo ./scripts/manage-services.sh status
   ```

3. **Verify no restart loops**:
   ```bash
   # Check that restart counter stays low
   sudo systemctl status python3-validity.service
   
   # Monitor logs for graceful exits instead of crashes
   sudo journalctl -u python3-validity.service --since "5 minutes ago"
   ```

## Expected Behavior After Fix

- **No Restart Loops**: `python3-validity` service should not repeatedly restart
- **Graceful Coexistence**: Both services can run simultaneously when properly coordinated
- **Clean Logs**: Error messages should be informative rather than crash traces
- **Stable Operation**: Services should remain stable during normal operation

## Troubleshooting

If issues persist:

1. **Check USB device permissions**:
   ```bash
   lsusb | grep -i validity
   ls -la /dev/bus/usb/
   ```

2. **Verify service order**:
   ```bash
   sudo systemctl list-dependencies python3-validity.service
   ```

3. **Check for hardware issues**:
   ```bash
   dmesg | grep -i usb | tail -20
   ```

4. **Reset services completely**:
   ```bash
   sudo ./scripts/manage-services.sh stop
   sleep 5
   sudo ./scripts/manage-services.sh start
   ```

This fix should resolve the USB device conflict issue and provide stable operation of both fingerprint services.
