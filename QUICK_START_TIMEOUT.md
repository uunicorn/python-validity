# Quick Start: Timeout-Based Scanning

## What Changed?

The fingerprint scanner now uses a **5-second timeout** instead of adaptive polling:
- ✅ Scans for 5 seconds (~10 scan attempts at 0.5s intervals)
- ⏹️ Cancels to password after timeout
- ⌨️ No manual retry needed - just use password

## Quick Setup

### 1. Default Configuration (Recommended)
No configuration needed! The defaults work for most users:
- 5-second timeout
- Automatic fallback to password after timeout
- 0.5-second polling interval
- Automatic keyboard detection

### 2. Custom Configuration (Optional)

Create or edit: `/etc/python-validity/config.ini`

```ini
[scanning]
# How long to scan before canceling (seconds)
# At 0.5s intervals, 5.0s = ~10 scan attempts
scan_timeout = 5.0

# How often to check for fingerprint (seconds)
poll_interval = 0.5

# Maximum timeout attempts before canceling (default: 1 = cancel on first timeout)
# Set to 3 if you want multiple retry opportunities
max_attempts = 1

[logging]
# Set to DEBUG to see detailed logs
level = INFO
```

### 3. Restart Service

```bash
sudo systemctl restart python3-validity
```

## Common Scenarios

### Lock Screen
1. Lock screen and walk away
2. Come back, press any key
3. Fingerprint detection starts automatically
4. Place finger to unlock

### Sudo Commands
1. Run `sudo command`
2. Fingerprint detection starts (5 seconds = ~10 scan attempts)
3. Either:
   - Use fingerprint within 5 seconds, OR
   - Wait for timeout → automatic password fallback
4. Type password to authenticate

### Scan Attempts Explained
- **5-second timeout** = **~10 individual scan attempts** (at 0.5s intervals)
- Each scan attempt checks if your finger is on the sensor
- After 10 failed scans (5 seconds), detection cancels
- You get multiple chances within the 5-second window
- After timeout: just type your password

## Customization Examples

### Longer Timeout (More Scan Attempts)
```ini
[scanning]
scan_timeout = 10.0  # 10s = ~20 scan attempts
```

### Shorter Timeout (Quick Fallback)
```ini
[scanning]
scan_timeout = 3.0  # 3s = ~6 scan attempts
```

### Faster Scanning (More Responsive)
```ini
[scanning]
poll_interval = 0.3  # Scan every 0.3s instead of 0.5s
```

### Allow Manual Retries (Multiple Timeout Windows)
```ini
[scanning]
max_attempts = 3  # Allow 3 timeout windows before canceling
# Total time: 5s × 3 = 15 seconds maximum
```

## Troubleshooting

### Detection Doesn't Restart
**Problem**: Pressing keys doesn't restart detection

**Fix**: Check service logs
```bash
journalctl -u python3-validity -f
```

### Timeout Too Short/Long
**Problem**: Detection pauses too quickly or waits too long

**Fix**: Adjust `scan_timeout` in config file

### High CPU Usage
**Problem**: Service uses too much CPU

**Fix**: Increase `poll_interval` to 1.0 or higher

## Testing

Test the new behavior:
```bash
cd /home/www/DEV-trunk/python-validity
./test_timeout_scanning.py
```

## More Information

See full documentation: `TIMEOUT_BASED_SCANNING.md`

## Key Benefits

- 🔋 **Lower power usage** - No scanning when idle
- 🎯 **Predictable behavior** - Clear 10-second timeout
- ⌨️ **Smart restart** - Automatically resumes on keyboard input
- 🚀 **Simpler config** - Just 2 main settings vs 7+ before
