#!/usr/bin/env python3

"""
Test script for timeout-based fingerprint scanning.
This script verifies the new timeout and keyboard input restart behavior.
"""

import sys
import time
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from validitysensor.config import SCAN_TIMEOUT, SCAN_POLL_INTERVAL
from validitysensor.input_watcher import create_input_watcher

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def test_configuration():
    """Test that configuration values are loaded correctly."""
    print("\n=== Configuration Test ===")
    print(f"Scan Timeout: {SCAN_TIMEOUT}s")
    print(f"Poll Interval: {SCAN_POLL_INTERVAL}s")
    
    assert SCAN_TIMEOUT > 0, "Scan timeout must be positive"
    assert SCAN_POLL_INTERVAL > 0, "Poll interval must be positive"
    print("✓ Configuration values are valid")

def test_input_watcher():
    """Test input watcher creation and basic functionality."""
    print("\n=== Input Watcher Test ===")
    
    # Create input watcher
    watcher = create_input_watcher()
    print(f"✓ Created input watcher: {type(watcher).__name__}")
    
    # Test callback setting
    callback_called = []
    
    def test_callback():
        callback_called.append(True)
        print("✓ Callback was called")
    
    watcher.set_resume_callback(test_callback)
    print("✓ Set resume callback")
    
    # Start watching
    watcher.start_watching()
    print("✓ Started watching for input")
    
    # Give user time to test
    print("\n>>> Press any key within 5 seconds to test input detection...")
    time.sleep(5)
    
    # Stop watching
    watcher.stop_watching()
    print("✓ Stopped watching")
    
    if callback_called:
        print("✓ Input detection working - callback was triggered")
    else:
        print("⚠ No input detected - this is OK if you didn't press any keys")

def test_timeout_simulation():
    """Simulate the timeout behavior without actual sensor."""
    print("\n=== Timeout Simulation Test ===")
    
    scan_timeout = SCAN_TIMEOUT
    poll_interval = SCAN_POLL_INTERVAL
    start_time = time.time()
    scan_active = True
    input_detected = []
    
    # Create input watcher
    watcher = create_input_watcher()
    
    def on_input():
        nonlocal start_time, scan_active
        if not scan_active:
            print(f"[{time.time() - start_time:.1f}s] Keyboard input detected - restarting")
            start_time = time.time()
            scan_active = True
            input_detected.append(True)
    
    watcher.set_resume_callback(on_input)
    watcher.start_watching()
    
    print(f"Simulating scanning with {scan_timeout}s timeout...")
    print(">>> Press any key after timeout to test restart\n")
    
    scan_count = 0
    try:
        for i in range(50):  # Run for up to 25 seconds
            elapsed = time.time() - start_time
            
            if elapsed >= scan_timeout and scan_active:
                print(f"[{elapsed:.1f}s] Timeout reached - pausing detection")
                scan_active = False
            
            if scan_active:
                scan_count += 1
                print(f"[{elapsed:.1f}s] Scan #{scan_count} (active)", end='\r')
            else:
                print(f"[{elapsed:.1f}s] Waiting for keyboard input...", end='\r')
            
            time.sleep(poll_interval)
            
            # Exit if we've tested restart
            if input_detected:
                print(f"\n[{time.time() - start_time:.1f}s] Restart successful!")
                break
    
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    
    finally:
        watcher.stop_watching()
    
    print(f"\n✓ Completed {scan_count} scans")
    if input_detected:
        print("✓ Input detection and restart working correctly")
    else:
        print("⚠ No restart tested - press a key after timeout next time")

def test_multiple_cycles():
    """Test multiple timeout/restart cycles."""
    print("\n=== Multiple Cycle Test ===")
    
    scan_timeout = 3.0  # Shorter timeout for testing
    poll_interval = 0.5
    cycles_completed = 0
    max_cycles = 3
    
    start_time = time.time()
    scan_active = True
    
    watcher = create_input_watcher()
    
    def on_input():
        nonlocal start_time, scan_active, cycles_completed
        if not scan_active:
            cycles_completed += 1
            print(f"\n[Cycle {cycles_completed}] Input detected - restarting")
            start_time = time.time()
            scan_active = True
    
    watcher.set_resume_callback(on_input)
    watcher.start_watching()
    
    print(f"Testing {max_cycles} timeout/restart cycles (3s timeout)")
    print(">>> Press a key each time detection pauses\n")
    
    try:
        iteration = 0
        while cycles_completed < max_cycles and iteration < 100:
            elapsed = time.time() - start_time
            
            if elapsed >= scan_timeout and scan_active:
                print(f"\n[Cycle {cycles_completed + 1}] Timeout - waiting for input...")
                scan_active = False
            
            if scan_active:
                print(f"Active: {elapsed:.1f}s", end='\r')
            else:
                print(f"Paused: waiting for input (cycle {cycles_completed}/{max_cycles})", end='\r')
            
            time.sleep(poll_interval)
            iteration += 1
    
    except KeyboardInterrupt:
        print("\n\nTest interrupted")
    
    finally:
        watcher.stop_watching()
    
    print(f"\n✓ Completed {cycles_completed}/{max_cycles} cycles")

def main():
    """Run all tests."""
    print("=" * 60)
    print("Timeout-Based Scanning Test Suite")
    print("=" * 60)
    
    try:
        test_configuration()
        test_input_watcher()
        test_timeout_simulation()
        
        # Ask if user wants to test multiple cycles
        print("\n" + "=" * 60)
        response = input("Run multiple cycle test? (y/n): ").strip().lower()
        if response == 'y':
            test_multiple_cycles()
        
        print("\n" + "=" * 60)
        print("All tests completed!")
        print("=" * 60)
        
    except Exception as e:
        logging.exception("Test failed with error")
        print(f"\n✗ Test failed: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
