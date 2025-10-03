#!/usr/bin/env python3

"""
Activity monitoring for python-validity to detect user interaction.
This helps optimize fingerprint scanning by detecting when the user is active.
"""

import os
import time
import logging
import threading
from pathlib import Path

class ActivityMonitor:
    """Monitor user activity to optimize fingerprint scanning."""
    
    def __init__(self):
        self.last_activity_time = time.time()
        self.monitoring = False
        self.monitor_thread = None
        self._stop_event = threading.Event()
        
    def start_monitoring(self):
        """Start monitoring user activity."""
        if self.monitoring:
            return
            
        self.monitoring = True
        self._stop_event.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logging.debug('Activity monitoring started')
    
    def stop_monitoring(self):
        """Stop monitoring user activity."""
        if not self.monitoring:
            return
            
        self.monitoring = False
        self._stop_event.set()
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        logging.debug('Activity monitoring stopped')
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while not self._stop_event.wait(1.0):  # Check every second
            try:
                activity_detected = self._check_activity()
                if activity_detected:
                    self.last_activity_time = time.time()
            except Exception as e:
                logging.debug(f'Error checking activity: {e}')
    
    def _check_activity(self):
        """Check for recent user activity."""
        try:
            # Check X11 idle time if available
            if self._check_x11_idle():
                return True
                
            # Check input device activity
            if self._check_input_devices():
                return True
                
            # Check system load as a fallback
            if self._check_system_activity():
                return True
                
        except Exception as e:
            logging.debug(f'Activity check error: {e}')
            
        return False
    
    def _check_x11_idle(self):
        """Check X11 idle time using xprintidle if available."""
        try:
            import subprocess
            result = subprocess.run(['xprintidle'], capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                idle_ms = int(result.stdout.strip())
                # Consider active if idle time is less than 5 seconds
                return idle_ms < 5000
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, ValueError):
            pass
        return False
    
    def _check_input_devices(self):
        """Check input device activity by monitoring /dev/input/."""
        try:
            input_dir = Path('/dev/input')
            if not input_dir.exists():
                return False
                
            # Check modification times of input event files
            current_time = time.time()
            for event_file in input_dir.glob('event*'):
                try:
                    stat = event_file.stat()
                    # Check if modified in the last 2 seconds
                    if current_time - stat.st_mtime < 2.0:
                        return True
                except (OSError, PermissionError):
                    continue
                    
        except Exception as e:
            logging.debug(f'Input device check error: {e}')
            
        return False
    
    def _check_system_activity(self):
        """Check system activity as a fallback indicator."""
        try:
            # Check if load average indicates recent activity
            load1, load5, load15 = os.getloadavg()
            # Consider active if 1-minute load is above a threshold
            return load1 > 0.5
        except Exception as e:
            logging.debug(f'System activity check error: {e}')
            
        return False
    
    def get_seconds_since_activity(self):
        """Get seconds since last detected activity."""
        return time.time() - self.last_activity_time
    
    def is_user_active(self, threshold_seconds=10):
        """Check if user has been active within threshold."""
        return self.get_seconds_since_activity() < threshold_seconds
    
    def should_use_aggressive_polling(self, threshold_seconds=30):
        """Determine if we should use aggressive polling based on recent activity."""
        return self.is_user_active(threshold_seconds)

# Global activity monitor instance
activity_monitor = ActivityMonitor()
