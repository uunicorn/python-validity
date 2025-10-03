#!/usr/bin/env python3

"""
Input event watcher for pause/resume functionality.
Monitors keyboard and mouse events to trigger fingerprint scanning resume.
"""

import os
import select
import threading
import logging
import time
from pathlib import Path
import struct

class InputWatcher:
    """Watch for keyboard and mouse input events to resume fingerprint scanning."""
    
    def __init__(self):
        self.watching = False
        self.watch_thread = None
        self._stop_event = threading.Event()
        self._resume_callback = None
        self.input_devices = []
        
    def set_resume_callback(self, callback):
        """Set callback to call when input is detected."""
        self._resume_callback = callback
    
    def start_watching(self):
        """Start watching for input events."""
        if self.watching:
            return
            
        self.watching = True
        self._stop_event.clear()
        self._find_input_devices()
        
        if self.input_devices:
            self.watch_thread = threading.Thread(target=self._watch_loop, daemon=True)
            self.watch_thread.start()
            logging.debug(f'Input watching started on {len(self.input_devices)} devices')
        else:
            logging.warning('No accessible input devices found for watching')
    
    def stop_watching(self):
        """Stop watching for input events."""
        if not self.watching:
            return
            
        self.watching = False
        self._stop_event.set()
        
        if self.watch_thread:
            self.watch_thread.join(timeout=1.0)
        
        # Close any open file descriptors
        for device_info in self.input_devices:
            if 'fd' in device_info and device_info['fd'] is not None:
                try:
                    os.close(device_info['fd'])
                except OSError:
                    pass
                device_info['fd'] = None
        
        logging.debug('Input watching stopped')
    
    def _find_input_devices(self):
        """Find accessible input devices."""
        self.input_devices = []
        input_dir = Path('/dev/input')
        
        if not input_dir.exists():
            return
        
        # Look for event devices (keyboards, mice, touchpads)
        for event_file in sorted(input_dir.glob('event*')):
            try:
                # Try to open the device
                fd = os.open(str(event_file), os.O_RDONLY | os.O_NONBLOCK)
                device_info = {
                    'path': str(event_file),
                    'fd': fd,
                    'name': self._get_device_name(fd)
                }
                self.input_devices.append(device_info)
                logging.debug(f'Added input device: {device_info["name"]} ({event_file})')
                
            except (OSError, PermissionError) as e:
                logging.debug(f'Cannot access {event_file}: {e}')
                continue
    
    def _get_device_name(self, fd):
        """Get the name of an input device."""
        try:
            # Use EVIOCGNAME ioctl to get device name
            import fcntl
            name_buffer = bytearray(256)
            fcntl.ioctl(fd, 0x80ff4506, name_buffer)  # EVIOCGNAME(256)
            return name_buffer.rstrip(b'\x00').decode('utf-8', errors='ignore')
        except (OSError, ImportError):
            return 'Unknown Device'
    
    def _watch_loop(self):
        """Main watching loop using select()."""
        if not self.input_devices:
            return
        
        # Prepare file descriptors for select
        fd_list = [dev['fd'] for dev in self.input_devices if dev['fd'] is not None]
        
        while not self._stop_event.is_set():
            try:
                # Use select with timeout to check for input
                ready, _, _ = select.select(fd_list, [], [], 0.5)
                
                if ready:
                    # Input detected on one or more devices
                    self._handle_input_detected(ready)
                    
            except (OSError, ValueError) as e:
                logging.debug(f'Select error in input watcher: {e}')
                break
    
    def _handle_input_detected(self, ready_fds):
        """Handle detected input events."""
        # Read and discard the actual events (we just care that something happened)
        for fd in ready_fds:
            try:
                # Read available data to clear the buffer
                os.read(fd, 1024)
            except OSError:
                pass
        
        logging.debug('Input activity detected - triggering resume')
        
        # Call the resume callback if set
        if self._resume_callback:
            try:
                self._resume_callback()
            except Exception as e:
                logging.error(f'Error in resume callback: {e}')

# Alternative implementation using inotify for file modification watching
class FileWatcher:
    """Alternative input watcher using inotify on /dev/input/."""
    
    def __init__(self):
        self.watching = False
        self.watch_thread = None
        self._stop_event = threading.Event()
        self._resume_callback = None
    
    def set_resume_callback(self, callback):
        """Set callback to call when input is detected."""
        self._resume_callback = callback
    
    def start_watching(self):
        """Start watching input directory for modifications."""
        if self.watching:
            return
            
        try:
            import inotify_simple
            self.watching = True
            self._stop_event.clear()
            self.watch_thread = threading.Thread(target=self._inotify_loop, daemon=True)
            self.watch_thread.start()
            logging.debug('File-based input watching started')
        except ImportError:
            logging.warning('inotify_simple not available, cannot use file watcher')
    
    def stop_watching(self):
        """Stop watching for input events."""
        if not self.watching:
            return
            
        self.watching = False
        self._stop_event.set()
        
        if self.watch_thread:
            self.watch_thread.join(timeout=1.0)
        
        logging.debug('File-based input watching stopped')
    
    def _inotify_loop(self):
        """Watch /dev/input/ for file modifications."""
        try:
            import inotify_simple
            
            inotify = inotify_simple.INotify()
            watch_flags = inotify_simple.flags.MODIFY
            
            # Watch the input directory
            wd = inotify.add_watch('/dev/input', watch_flags)
            
            while not self._stop_event.is_set():
                # Check for events with timeout
                events = inotify.read(timeout=500)  # 500ms timeout
                
                if events:
                    logging.debug('Input file modification detected - triggering resume')
                    if self._resume_callback:
                        try:
                            self._resume_callback()
                        except Exception as e:
                            logging.error(f'Error in resume callback: {e}')
                    
                    # Small delay to avoid rapid triggering
                    time.sleep(0.1)
                    
        except Exception as e:
            logging.error(f'Error in inotify loop: {e}')
        finally:
            try:
                inotify.close()
            except:
                pass

# Factory function to create the best available watcher
def create_input_watcher():
    """Create the best available input watcher for the system."""
    
    # Try direct event reading first (more reliable)
    watcher = InputWatcher()
    watcher._find_input_devices()
    
    if watcher.input_devices:
        logging.debug('Using direct input event watcher')
        return watcher
    
    # Fall back to file modification watching
    try:
        import inotify_simple
        logging.debug('Using inotify file watcher')
        return FileWatcher()
    except ImportError:
        pass
    
    # Return the direct watcher even if no devices (it will log warnings)
    logging.warning('No optimal input watcher available, using basic implementation')
    return watcher
