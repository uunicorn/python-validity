#!/usr/bin/env python3
"""
Debug script to check database status and storage information
for the python-validity fingerprint sensor.
"""

import sys
import os

# Add the validitysensor module to the path
sys.path.insert(0, '/usr/lib/python3.13/site-packages')

try:
    from validitysensor.init import init_all
    from validitysensor.db import Db
    from validitysensor.tls import tls
    
    def check_database_status():
        """Check the database storage status and existing records."""
        print("Initializing sensor...")
        try:
            init_all()
            print("Sensor initialized successfully.")
            
            # Create database instance
            db = Db()
            
            # Get database info
            print("\n=== Database Information ===")
            db_info = db.db_info()
            print(f"Total space: {db_info.total} bytes")
            print(f"Used space: {db_info.used} bytes") 
            print(f"Free space: {db_info.free} bytes")
            print(f"Records count: {db_info.records}")
            print(f"Usage: {(db_info.used / db_info.total * 100):.1f}%")
            
            if db_info.free < 1000:  # Less than 1KB free
                print("⚠️  WARNING: Very low free space!")
            
            # Get user storage info
            print("\n=== User Storage Information ===")
            try:
                stg = db.get_user_storage(name='StgWindsor')
                print(f"Storage ID: {stg.dbid}")
                print(f"Storage name: {stg.name}")
                print(f"Users in storage: {len(stg.users)}")
                
                # List all users and their fingerprints
                print("\n=== Existing Users and Fingerprints ===")
                for i, user_info in enumerate(stg.users):
                    user = db.get_user(user_info['dbid'])
                    print(f"User {i+1}:")
                    print(f"  ID: {user.dbid}")
                    print(f"  Identity: {user.identity}")
                    print(f"  Fingerprints: {len(user.fingers)}")
                    for j, finger in enumerate(user.fingers):
                        print(f"    Finger {j+1}: subtype={finger['subtype']}, storage={finger['storage']}, size={finger['valueSize']}")
                
                if len(stg.users) == 0:
                    print("No users found in storage.")
                    
            except Exception as e:
                print(f"Error getting user storage: {e}")
            
        except Exception as e:
            print(f"Error during database check: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        return True
    
    def cleanup_database():
        """Attempt to clean up the database by removing old records."""
        print("\n=== Database Cleanup ===")
        try:
            db = Db()
            stg = db.get_user_storage(name='StgWindsor')
            
            print(f"Found {len(stg.users)} users in database")
            
            # Ask user if they want to delete all fingerprints
            response = input("Do you want to delete all existing fingerprints? (yes/no): ")
            if response.lower() in ['yes', 'y']:
                for user_info in stg.users:
                    try:
                        print(f"Deleting user record {user_info['dbid']}...")
                        db.del_record(user_info['dbid'])
                        print(f"Successfully deleted user {user_info['dbid']}")
                    except Exception as e:
                        print(f"Error deleting user {user_info['dbid']}: {e}")
                
                print("Database cleanup completed.")
                
                # Check database status after cleanup
                db_info = db.db_info()
                print(f"\nAfter cleanup:")
                print(f"Free space: {db_info.free} bytes")
                print(f"Records count: {db_info.records}")
            else:
                print("Cleanup cancelled.")
                
        except Exception as e:
            print(f"Error during cleanup: {e}")
            import traceback
            traceback.print_exc()
    
    if __name__ == "__main__":
        print("Python-Validity Database Status Checker")
        print("=" * 40)
        
        if check_database_status():
            print("\n" + "=" * 40)
            cleanup_response = input("\nWould you like to attempt database cleanup? (yes/no): ")
            if cleanup_response.lower() in ['yes', 'y']:
                cleanup_database()
        
        print("\nDone.")

except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure the python-validity package is properly installed.")
    sys.exit(1)
