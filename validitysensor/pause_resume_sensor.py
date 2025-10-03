#!/usr/bin/env python3

"""
Enhanced sensor with pause/resume capability based on input detection.
This extends the existing sensor with the ability to completely pause scanning
until user input is detected.
"""

import time
import logging
import threading
from .input_watcher import create_input_watcher
from .config import config

class PauseResumeMixin:
    """Mixin to add pause/resume functionality to the sensor."""
    
    def __init__(self):
        self.paused = False
        self.pause_timeout = config.get_float('scanning', 'pause_timeout', 30.0)
        self.pause_enabled = config.get_bool('scanning', 'pause_on_timeout', False)
        self.input_watcher = None
        self._pause_event = threading.Event()
        self._resume_event = threading.Event()
        
        # Set initial state
        self._resume_event.set()  # Start in resumed state
    
    def _setup_input_watcher(self):
        """Set up input watcher for resume detection."""
        if not self.pause_enabled:
            return
            
        if self.input_watcher is None:
            self.input_watcher = create_input_watcher()
            self.input_watcher.set_resume_callback(self._on_input_detected)
    
    def _on_input_detected(self):
        """Called when input is detected - resume scanning."""
        if self.paused:
            logging.debug('Input detected - resuming fingerprint scanning')
            self.resume_scanning()
    
    def pause_scanning(self):
        """Pause fingerprint scanning until input is detected."""
        if not self.pause_enabled or self.paused:
            return
            
        logging.info('Pausing fingerprint scanning - waiting for user input')
        self.paused = True
        self._resume_event.clear()
        
        # Start watching for input
        if self.input_watcher:
            self.input_watcher.start_watching()
    
    def resume_scanning(self):
        """Resume fingerprint scanning."""
        if not self.paused:
            return
            
        logging.info('Resuming fingerprint scanning')
        self.paused = False
        self._resume_event.set()
        
        # Stop watching for input
        if self.input_watcher:
            self.input_watcher.stop_watching()
    
    def is_paused(self):
        """Check if scanning is currently paused."""
        return self.paused
    
    def wait_for_resume(self, timeout=None):
        """Wait for scanning to be resumed."""
        return self._resume_event.wait(timeout)
    
    def should_pause_after_timeout(self, consecutive_failures, time_since_start):
        """Determine if scanning should be paused based on timeout."""
        if not self.pause_enabled:
            return False
            
        # Pause if we've been scanning for longer than pause_timeout
        # and have had multiple consecutive failures
        return (time_since_start > self.pause_timeout and 
                consecutive_failures > config.get_int('scanning', 'adaptive_threshold', 5))
    
    def cleanup_pause_resume(self):
        """Clean up pause/resume resources."""
        if self.input_watcher:
            self.input_watcher.stop_watching()

def create_enhanced_identify_method(original_identify):
    """Create an enhanced identify method with pause/resume capability."""
    
    def enhanced_identify(self, update_cb):
        """Enhanced identify method with pause/resume functionality."""
        from .config import (SCAN_BASE_INTERVAL, SCAN_MAX_INTERVAL, ADAPTIVE_POLLING_ENABLED, 
                           ADAPTIVE_THRESHOLD, ERROR_COOLDOWN, ADAPTIVE_DEBUG, LOCKSCREEN_OPTIMIZATION)
        from .activity_monitor import activity_monitor
        
        # Initialize pause/resume if not already done
        if not hasattr(self, 'paused'):
            PauseResumeMixin.__init__(self)
        
        self._setup_input_watcher()
        
        last_error_time = 0
        error_cooldown = ERROR_COOLDOWN
        scan_interval = SCAN_BASE_INTERVAL
        max_scan_interval = SCAN_MAX_INTERVAL
        current_scan_interval = scan_interval
        consecutive_failures = 0
        start_time = time.time()
        
        # Start activity monitoring if lockscreen optimization is enabled
        if LOCKSCREEN_OPTIMIZATION:
            activity_monitor.start_monitoring()
        
        try:
            while True:
                current_time = time.time()
                time_since_start = current_time - start_time
                
                # Check if we should pause due to timeout
                if self.should_pause_after_timeout(consecutive_failures, time_since_start):
                    logging.info(f'Pausing after {time_since_start:.1f}s with {consecutive_failures} failures')
                    update_cb(Exception('Pausing scan - touch keyboard/mouse to resume'))
                    self.pause_scanning()
                    
                    # Wait for resume (blocking)
                    if not self.wait_for_resume():
                        # If we get here, something went wrong
                        break
                    
                    # Reset counters after resume
                    consecutive_failures = 0
                    current_scan_interval = scan_interval
                    start_time = time.time()
                    logging.info('Scanning resumed')
                    continue
                
                # Check if we're paused (shouldn't happen here, but safety check)
                if self.is_paused():
                    if not self.wait_for_resume(timeout=1.0):
                        continue
                
                try:
                    from .sensor import glow_start_scan, glow_end_scan, CaptureMode
                    
                    glow_start_scan()
                    try:
                        self.capture(CaptureMode.IDENTIFY)
                        result = self.match_finger()
                        if result is not None:
                            try:
                                return result
                            finally:
                                glow_end_scan()
                        
                        # If we get here, the finger wasn't recognized
                        consecutive_failures += 1
                        
                        # Adaptive polling logic
                        if ADAPTIVE_POLLING_ENABLED and consecutive_failures > ADAPTIVE_THRESHOLD:
                            base_multiplier = consecutive_failures / ADAPTIVE_THRESHOLD
                            
                            # Use activity monitoring to adjust polling strategy
                            if LOCKSCREEN_OPTIMIZATION and not activity_monitor.should_use_aggressive_polling():
                                current_scan_interval = min(max_scan_interval * 2, scan_interval * base_multiplier * 2)
                                if ADAPTIVE_DEBUG:
                                    logging.debug(f'User inactive - extended polling interval to {current_scan_interval:.1f}s')
                            else:
                                current_scan_interval = min(max_scan_interval, scan_interval * base_multiplier)
                                if ADAPTIVE_DEBUG:
                                    logging.debug(f'Adaptive polling: interval {current_scan_interval:.1f}s after {consecutive_failures} failures')
                        
                        if current_time - last_error_time > error_cooldown:
                            update_cb(Exception('Finger not recognized, please try again'))
                            last_error_time = current_time
                            
                    except Exception as e:
                        logging.debug('Error during capture: %s', e)
                        consecutive_failures += 1
                        current_time = time.time()
                        if current_time - last_error_time > error_cooldown:
                            update_cb(Exception('Scan error, please try again'))
                            last_error_time = current_time
                    finally:
                        try:
                            glow_end_scan()
                        except Exception as e:
                            logging.debug('Error during scan cleanup: %s', e)
                    
                    # Use adaptive interval
                    time.sleep(current_scan_interval)
                    
                except Exception as e:
                    logging.error('Unexpected error during identification: %s', e)
                    update_cb(e)
                    consecutive_failures = 0
                    current_scan_interval = scan_interval
                    time.sleep(1)
                    
        except Exception as e:
            logging.error('Fatal error in enhanced identify: %s', e)
            raise
        finally:
            # Cleanup
            if LOCKSCREEN_OPTIMIZATION:
                activity_monitor.stop_monitoring()
            self.cleanup_pause_resume()
    
    return enhanced_identify
