# Final Behavior Summary: Timeout-Based Scanning

## Overview

The fingerprint scanner uses a **5-second timeout window** with **automatic password fallback** after the timeout expires.

## Key Concept: Timeout = Multiple Scan Attempts

```
5-second timeout = ~10 individual scan attempts (at 0.5s intervals)

Timeline:
0.0s - Scan #1
0.5s - Scan #2
1.0s - Scan #3
1.5s - Scan #4
2.0s - Scan #5
2.5s - Scan #6
3.0s - Scan #7
3.5s - Scan #8
4.0s - Scan #9
4.5s - Scan #10
5.0s - TIMEOUT → Cancel to password
```

## Default Configuration

```ini
[scanning]
scan_timeout = 5.0    # 5 seconds = ~10 scan attempts
poll_interval = 0.5   # Scan every 0.5 seconds
max_attempts = 1      # Cancel after first timeout (no retries)
```

## User Experience Flow

### Scenario 1: Successful Authentication
```
00:00 - User runs: sudo apt update
00:00 - Fingerprint detection starts
00:02 - User places finger (scan #4)
00:02 - Match found ✓
00:02 - Command executes
```

### Scenario 2: Timeout → Password Fallback
```
00:00 - User runs: sudo apt update
00:00 - Fingerprint detection starts
        (Scans #1-10 over 5 seconds, no finger detected)
00:05 - Timeout reached
00:05 - "Maximum attempts reached - canceling"
00:05 - Password prompt appears
00:05 - User types password
00:10 - Command executes
```

### Scenario 3: User Prefers Password
```
00:00 - User runs: sudo apt update
00:00 - Fingerprint detection starts
00:01 - User starts typing password immediately
        (Fingerprint detection continues in background)
00:05 - Timeout reached, detection cancels
00:05 - Password already entered, command executes
```

## Why This Design?

### 1. Multiple Chances Within Timeout
- User gets **~10 scan attempts** in the 5-second window
- No need to place finger perfectly on first try
- Natural for users who need a moment to position their finger

### 2. Automatic Fallback
- No manual intervention needed after timeout
- No "press key to retry" prompts
- Clean transition to password authentication

### 3. No Infinite Loops
- Clear 5-second limit
- Prevents USB device stress
- Reduces power consumption
- Better for battery life

### 4. Predictable Behavior
- Users know they have 5 seconds
- After 5 seconds, just type password
- No confusion about retry mechanisms

## Comparison: Old vs New

### Old Adaptive Polling (Deprecated)
```
00:00 - Start scanning (0.5s interval)
00:05 - Still scanning (1.0s interval)
00:10 - Still scanning (2.0s interval)
00:15 - Still scanning (3.0s interval)
00:20 - Still scanning (3.0s interval)
... continues indefinitely
```
**Problem**: Never stops, wastes resources

### New Timeout-Based (Current)
```
00:00 - Start scanning (0.5s interval)
00:05 - Timeout → Cancel to password
```
**Solution**: Clean timeout, automatic fallback

## Configuration Flexibility

### Default (Recommended)
```ini
scan_timeout = 5.0
max_attempts = 1
```
- 5 seconds = ~10 scan attempts
- Cancel immediately on timeout
- **Total time**: 5 seconds

### Patient Users
```ini
scan_timeout = 10.0
max_attempts = 1
```
- 10 seconds = ~20 scan attempts
- More time to position finger
- **Total time**: 10 seconds

### Multiple Retry Windows
```ini
scan_timeout = 5.0
max_attempts = 3
```
- 5 seconds per window
- 3 windows with keyboard restart between
- **Total time**: Up to 15 seconds

### Quick Fallback
```ini
scan_timeout = 3.0
max_attempts = 1
```
- 3 seconds = ~6 scan attempts
- Fast fallback to password
- **Total time**: 3 seconds

## Technical Details

### Scan Frequency Calculation
```
Number of scans = scan_timeout / poll_interval
Example: 5.0s / 0.5s = 10 scans
```

### Total Maximum Time
```
Total time = scan_timeout × max_attempts
Example: 5.0s × 1 = 5 seconds
```

### Resource Usage
- **Active scanning**: 0.5-1% CPU, USB transactions every 0.5s
- **After timeout**: ~0% CPU, no USB transactions
- **Power impact**: Minimal (only 5 seconds of active scanning)

## Benefits

### For Users
✅ Multiple chances to place finger (10 attempts in 5 seconds)
✅ Automatic password fallback (no manual intervention)
✅ Predictable behavior (5-second window)
✅ No confusion (clear timeout)

### For System
✅ Reduced USB stress (only 5 seconds of polling)
✅ Lower power consumption (stops after timeout)
✅ No infinite loops (guaranteed termination)
✅ Better battery life (minimal active time)

### For Developers
✅ Simple configuration (3 parameters)
✅ Clear behavior (timeout → cancel)
✅ Easy to test (5-second window)
✅ Maintainable code (no complex adaptive logic)

## Real-World Usage

### Lock Screen
- User wakes screen
- 5 seconds to place finger
- If timeout: type password
- **Result**: Fast unlock or quick fallback

### Sudo Commands
- User runs sudo command
- 5 seconds to place finger
- If timeout: type password
- **Result**: Efficient authentication

### SSH/Terminal
- User connects to server
- 5 seconds to place finger
- If timeout: type password
- **Result**: No hanging sessions

## Summary

The final design provides:
- **~10 scan attempts** within a 5-second window
- **Automatic password fallback** after timeout
- **No manual retries** needed (unless configured)
- **Predictable behavior** users can understand
- **Resource efficient** (stops after 5 seconds)

This balances user convenience (multiple scan chances) with system efficiency (guaranteed timeout) and provides a clean, predictable authentication experience.
