#!/usr/bin/env python3
"""
Test script to verify that duplicate fingerprint prevention works correctly.

This script simulates the enrollment process to test that:
1. Re-enrolling the same finger replaces the old template
2. Database space is freed when old templates are removed
3. Different fingers can coexist for the same user
"""

import sys
import os

# Add the validitysensor module to the path
sys.path.insert(0, '/usr/lib/python3.13/site-packages')

try:
    from validitysensor.init import init_all
    from validitysensor.db import Db
    from validitysensor.sid import SidIdentity
    
    def test_duplicate_prevention():
        """Test that duplicate fingerprints are properly replaced."""
        print("=== Testing Duplicate Fingerprint Prevention ===")
        
        try:
            # Initialize the sensor
            init_all()
            db = Db()
            
            # Create a test user identity
            test_identity = SidIdentity("S-1-5-21-1234567890-1234567890-1234567890-1001")
            
            # Check if user already exists
            existing_user = db.lookup_user(test_identity)
            if existing_user:
                print(f"Found existing test user: {existing_user.identity} (ID: {existing_user.dbid})")
                user_id = existing_user.dbid
            else:
                print("Creating new test user...")
                user_id = db.new_user(test_identity)
                print(f"Created test user with ID: {user_id}")
            
            # Test data - simulate fingerprint templates
            template1 = b"FAKE_FINGERPRINT_TEMPLATE_1_" + b"X" * 1000  # 1KB template
            template2 = b"FAKE_FINGERPRINT_TEMPLATE_2_" + b"Y" * 1500  # 1.5KB template
            template3 = b"FAKE_FINGERPRINT_TEMPLATE_3_" + b"Z" * 800   # 0.8KB template
            
            subtype_thumb = 1  # Right thumb
            subtype_index = 2  # Right index finger
            
            print(f"\n--- Test 1: Initial enrollment of right thumb ---")
            db_info_before = db.db_info()
            print(f"Database free space before: {db_info_before.free} bytes")
            
            finger1_id = db.new_finger(user_id, template1, subtype_thumb)
            print(f"Enrolled right thumb, got record ID: {finger1_id}")
            
            db_info_after = db.db_info()
            print(f"Database free space after: {db_info_after.free} bytes")
            space_used = db_info_before.free - db_info_after.free
            print(f"Space used: {space_used} bytes")
            
            print(f"\n--- Test 2: Re-enrollment of right thumb (should replace) ---")
            db_info_before = db.db_info()
            print(f"Database free space before: {db_info_before.free} bytes")
            
            finger2_id = db.new_finger(user_id, template2, subtype_thumb)
            print(f"Re-enrolled right thumb, got record ID: {finger2_id}")
            
            db_info_after = db.db_info()
            print(f"Database free space after: {db_info_after.free} bytes")
            space_change = db_info_after.free - db_info_before.free
            
            if space_change > 0:
                print(f"✅ SUCCESS: Space was freed ({space_change} bytes) - old template was replaced!")
            elif space_change == 0:
                print(f"⚠️  NEUTRAL: No space change - templates might be same size")
            else:
                print(f"❌ ISSUE: Space decreased ({-space_change} bytes) - old template might not have been removed")
            
            print(f"\n--- Test 3: Enrollment of different finger (should coexist) ---")
            db_info_before = db.db_info()
            print(f"Database free space before: {db_info_before.free} bytes")
            
            finger3_id = db.new_finger(user_id, template3, subtype_index)
            print(f"Enrolled right index finger, got record ID: {finger3_id}")
            
            db_info_after = db.db_info()
            print(f"Database free space after: {db_info_after.free} bytes")
            space_used = db_info_before.free - db_info_after.free
            print(f"Space used: {space_used} bytes")
            
            print(f"\n--- Test 4: Check final user state ---")
            final_user = db.get_user(user_id)
            print(f"User {final_user.identity} now has {len(final_user.fingers)} fingerprint(s):")
            for i, finger in enumerate(final_user.fingers):
                print(f"  Finger {i+1}: ID={finger['dbid']}, subtype={finger['subtype']}, size={finger['valueSize']} bytes")
            
            # Verify we have exactly 2 fingerprints (thumb + index)
            thumb_fingers = [f for f in final_user.fingers if f['subtype'] == subtype_thumb]
            index_fingers = [f for f in final_user.fingers if f['subtype'] == subtype_index]
            
            print(f"\nVerification:")
            print(f"Right thumb fingerprints: {len(thumb_fingers)} (should be 1)")
            print(f"Right index fingerprints: {len(index_fingers)} (should be 1)")
            
            if len(thumb_fingers) == 1 and len(index_fingers) == 1:
                print("✅ SUCCESS: Duplicate prevention working correctly!")
                return True
            else:
                print("❌ FAILURE: Duplicate prevention not working as expected!")
                return False
                
        except Exception as e:
            print(f"❌ Error during test: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def cleanup_test_user():
        """Clean up the test user."""
        print("\n=== Cleaning up test user ===")
        try:
            init_all()
            db = Db()
            
            test_identity = SidIdentity("S-1-5-21-1234567890-1234567890-1234567890-1001")
            user = db.lookup_user(test_identity)
            
            if user:
                print(f"Removing test user {user.identity} (ID: {user.dbid})")
                db.del_record(user.dbid)
                print("✅ Test user removed successfully")
            else:
                print("No test user found to clean up")
                
        except Exception as e:
            print(f"Error during cleanup: {e}")
    
    if __name__ == "__main__":
        print("Duplicate Fingerprint Prevention Test")
        print("=" * 40)
        
        success = test_duplicate_prevention()
        
        cleanup_choice = input("\nClean up test user? (y/n): ").strip().lower()
        if cleanup_choice in ['y', 'yes']:
            cleanup_test_user()
        
        if success:
            print("\n✅ All tests passed!")
            sys.exit(0)
        else:
            print("\n❌ Some tests failed!")
            sys.exit(1)

except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Make sure the python-validity package is properly installed.")
    sys.exit(1)
