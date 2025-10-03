#!/usr/bin/env python3

"""
Test script for the new adaptive polling behavior in python-validity.
This script helps verify that the polling optimizations work correctly.
"""

import time
import logging
import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from validitysensor.config import config
from validitysensor.activity_monitor import activity_monitor

def test_config_loading():
    """Test that configuration loads correctly."""
    print("Testing configuration loading...")
    
    print(f"Base scan interval: {config.get_float('scanning', 'base_interval')}s")
    print(f"Max scan interval: {config.get_float('scanning', 'max_interval')}s")
    print(f"Adaptive polling enabled: {config.get_bool('scanning', 'adaptive_polling')}")
    print(f"Adaptive threshold: {config.get_int('scanning', 'adaptive_threshold')}")
    print(f"Error cooldown: {config.get_float('scanning', 'error_cooldown')}s")
    print(f"Lockscreen optimization: {config.get_bool('scanning', 'lockscreen_optimization')}")
    print(f"Config file location: {config.config_file}")
    
    # Create default config file if it doesn't exist
    if not config.config_file.exists():
        print(f"Creating default config file at {config.config_file}")
        config.save_default_config()
    
    print("✓ Configuration test passed\n")

def test_activity_monitor():
    """Test the activity monitoring functionality."""
    print("Testing activity monitor...")
    
    # Start monitoring
    activity_monitor.start_monitoring()
    print("Activity monitoring started")
    
    # Check initial state
    print(f"Seconds since activity: {activity_monitor.get_seconds_since_activity():.1f}")
    print(f"User active (10s threshold): {activity_monitor.is_user_active(10)}")
    print(f"Should use aggressive polling: {activity_monitor.should_use_aggressive_polling()}")
    
    # Wait a bit and check again
    print("Waiting 3 seconds...")
    time.sleep(3)
    
    print(f"Seconds since activity: {activity_monitor.get_seconds_since_activity():.1f}")
    print(f"User active (10s threshold): {activity_monitor.is_user_active(10)}")
    print(f"Should use aggressive polling: {activity_monitor.should_use_aggressive_polling()}")
    
    # Stop monitoring
    activity_monitor.stop_monitoring()
    print("Activity monitoring stopped")
    print("✓ Activity monitor test passed\n")

def simulate_polling_behavior():
    """Simulate the new polling behavior without actually scanning."""
    print("Simulating adaptive polling behavior...")
    
    from validitysensor.config import (SCAN_BASE_INTERVAL, SCAN_MAX_INTERVAL, 
                                     ADAPTIVE_POLLING_ENABLED, ADAPTIVE_THRESHOLD)
    
    scan_interval = SCAN_BASE_INTERVAL
    max_scan_interval = SCAN_MAX_INTERVAL
    current_scan_interval = scan_interval
    consecutive_failures = 0
    
    print(f"Initial scan interval: {current_scan_interval}s")
    
    # Start activity monitoring
    activity_monitor.start_monitoring()
    
    try:
        # Simulate several failed scans
        for i in range(15):
            consecutive_failures += 1
            
            if ADAPTIVE_POLLING_ENABLED and consecutive_failures > ADAPTIVE_THRESHOLD:
                base_multiplier = consecutive_failures / ADAPTIVE_THRESHOLD
                
                # Use activity monitoring to adjust polling strategy
                if not activity_monitor.should_use_aggressive_polling():
                    # User hasn't been active recently, use longer intervals
                    current_scan_interval = min(max_scan_interval * 2, scan_interval * base_multiplier * 2)
                    print(f"Failure {consecutive_failures}: User inactive - extended interval to {current_scan_interval:.1f}s")
                else:
                    # Normal adaptive polling
                    current_scan_interval = min(max_scan_interval, scan_interval * base_multiplier)
                    print(f"Failure {consecutive_failures}: Normal adaptive interval to {current_scan_interval:.1f}s")
            else:
                print(f"Failure {consecutive_failures}: Using base interval {current_scan_interval:.1f}s")
            
            # Simulate the sleep interval (shortened for demo)
            time.sleep(min(current_scan_interval, 1.0))
    
    finally:
        activity_monitor.stop_monitoring()
    
    print("✓ Polling simulation completed\n")

def show_recommendations():
    """Show recommendations for optimal configuration."""
    print("Recommendations for optimal fingerprint scanning:")
    print("=" * 50)
    
    print("1. For lock screen usage:")
    print("   - Enable lockscreen_optimization = true")
    print("   - Use adaptive_polling = true")
    print("   - Set base_interval = 0.5s for responsiveness")
    print("   - Set max_interval = 3.0s to save power")
    
    print("\n2. For login/sudo usage:")
    print("   - Can disable lockscreen_optimization = false")
    print("   - Keep adaptive_polling = true")
    print("   - Use shorter intervals for faster authentication")
    
    print("\n3. Power saving:")
    print("   - Increase base_interval to 1.0s")
    print("   - Increase max_interval to 5.0s")
    print("   - Enable all optimizations")
    
    print("\n4. Performance:")
    print("   - Decrease base_interval to 0.3s")
    print("   - Keep max_interval at 2.0s")
    print("   - May use more power but faster response")
    
    print(f"\nCurrent config file: {config.config_file}")
    print("Edit this file to customize behavior for your needs.")

def main():
    """Main test function."""
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    
    print("Python-Validity Adaptive Polling Test")
    print("=" * 40)
    
    try:
        test_config_loading()
        test_activity_monitor()
        simulate_polling_behavior()
        show_recommendations()
        
        print("✓ All tests completed successfully!")
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        logging.exception("Test error")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
