#!/usr/bin/env python3

"""
Test script for pause/resume functionality in python-validity.
This demonstrates the complete pause-on-timeout with resume-on-input behavior.
"""

import time
import sys
import logging
import threading
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from validitysensor.input_watcher import create_input_watcher
from validitysensor.config import config

def test_input_detection():
    """Test input detection capabilities."""
    print("Testing Input Detection")
    print("=" * 30)
    
    watcher = create_input_watcher()
    
    input_detected = threading.Event()
    
    def on_input():
        print("🎯 INPUT DETECTED!")
        input_detected.set()
    
    watcher.set_resume_callback(on_input)
    watcher.start_watching()
    
    print("Input watcher started. Try typing or moving the mouse...")
    print("Waiting 10 seconds for input...")
    
    if input_detected.wait(10):
        print("✓ Input detection working correctly")
        result = True
    else:
        print("✗ No input detected in 10 seconds")
        result = False
    
    watcher.stop_watching()
    return result

def simulate_pause_resume_scenario():
    """Simulate a complete pause/resume scenario."""
    print("\nSimulating Pause/Resume Scenario")
    print("=" * 35)
    
    # Enable pause functionality for this test
    config.config['scanning']['pause_on_timeout'] = 'true'
    config.config['scanning']['pause_timeout'] = '5.0'  # Short timeout for demo
    
    from validitysensor.pause_resume_sensor import PauseResumeMixin
    
    # Create a mock sensor with pause/resume capability
    class MockSensor(PauseResumeMixin):
        def __init__(self):
            super().__init__()
            self.scan_count = 0
        
        def simulate_scan_loop(self):
            """Simulate the scanning loop with pause/resume."""
            print("Starting simulated scan loop...")
            start_time = time.time()
            consecutive_failures = 0
            
            self._setup_input_watcher()
            
            try:
                while time.time() - start_time < 20:  # Run for 20 seconds max
                    current_time = time.time()
                    time_since_start = current_time - start_time
                    
                    # Check if we should pause
                    if self.should_pause_after_timeout(consecutive_failures, time_since_start):
                        print(f"⏸️  PAUSING after {time_since_start:.1f}s with {consecutive_failures} failures")
                        print("   Touch keyboard or move mouse to resume...")
                        self.pause_scanning()
                        
                        # Wait for resume
                        if self.wait_for_resume(timeout=15):  # 15 second timeout
                            print("▶️  RESUMED - continuing scan loop")
                            consecutive_failures = 0
                            start_time = time.time()  # Reset timer
                        else:
                            print("❌ Resume timeout - ending simulation")
                            break
                    
                    # Simulate a scan attempt
                    self.scan_count += 1
                    consecutive_failures += 1
                    print(f"   Scan {self.scan_count}: No finger detected (failure {consecutive_failures})")
                    
                    # Don't scan too fast during demo
                    time.sleep(1)
                    
            finally:
                self.cleanup_pause_resume()
            
            print(f"Simulation complete. Total scans: {self.scan_count}")
    
    sensor = MockSensor()
    sensor.simulate_scan_loop()

def show_implementation_details():
    """Show what's involved in implementing pause/resume."""
    print("\nImplementation Requirements")
    print("=" * 30)
    
    print("1. INPUT DETECTION:")
    print("   - Direct /dev/input/event* monitoring (requires permissions)")
    print("   - inotify watching of /dev/input/ directory")
    print("   - X11 idle time detection (xprintidle)")
    print("   - Fallback to file modification timestamps")
    
    print("\n2. SENSOR MODIFICATIONS:")
    print("   - Add pause/resume state management")
    print("   - Implement timeout-based pause triggers")
    print("   - Thread-safe resume signaling")
    print("   - Graceful cleanup of resources")
    
    print("\n3. CONFIGURATION OPTIONS:")
    print("   - pause_on_timeout: Enable/disable feature")
    print("   - pause_timeout: Seconds before pausing (default: 30)")
    print("   - input_detection_method: auto/direct/inotify")
    
    print("\n4. CHALLENGES:")
    print("   - Permissions for /dev/input/* access")
    print("   - Different input methods on different systems")
    print("   - Thread synchronization for pause/resume")
    print("   - Graceful handling of input detection failures")
    
    print("\n5. BENEFITS:")
    print("   - Near-zero CPU usage when paused")
    print("   - No USB polling during pause")
    print("   - Instant resume on user activity")
    print("   - Configurable timeout thresholds")

def check_permissions():
    """Check if we have the necessary permissions for input monitoring."""
    print("\nPermission Check")
    print("=" * 20)
    
    input_dir = Path('/dev/input')
    if not input_dir.exists():
        print("❌ /dev/input directory not found")
        return False
    
    accessible_devices = 0
    for event_file in input_dir.glob('event*'):
        try:
            with open(event_file, 'rb'):
                accessible_devices += 1
        except PermissionError:
            print(f"❌ No permission to read {event_file}")
        except Exception as e:
            print(f"⚠️  Error accessing {event_file}: {e}")
    
    if accessible_devices > 0:
        print(f"✓ Can access {accessible_devices} input devices")
        return True
    else:
        print("❌ No accessible input devices found")
        print("   Try running as root or adding user to 'input' group:")
        print("   sudo usermod -a -G input $USER")
        return False

def main():
    """Main test function."""
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    
    print("Python-Validity Pause/Resume Test")
    print("=" * 40)
    
    # Check system capabilities
    has_permissions = check_permissions()
    
    # Show implementation details
    show_implementation_details()
    
    if has_permissions:
        # Test input detection
        if test_input_detection():
            # Run full simulation
            simulate_pause_resume_scenario()
        else:
            print("⚠️  Input detection test failed, skipping simulation")
    else:
        print("⚠️  Insufficient permissions for full testing")
    
    print("\n" + "=" * 40)
    print("SUMMARY: Pause/Resume Implementation")
    print("=" * 40)
    print("✓ Input detection framework created")
    print("✓ Pause/resume sensor mixin implemented") 
    print("✓ Configuration options added")
    print("✓ Test framework developed")
    print("\nTo enable: Set pause_on_timeout = true in config")
    print("Requires: Permissions to read /dev/input/event* files")

if __name__ == '__main__':
    main()
