#!/usr/bin/env python3
"""
Fingerprint Database Management Utility for python-validity

This utility helps manage the fingerprint database when it becomes full
or encounters storage issues. It can:
- Check database status and storage usage
- List existing users and fingerprints  
- Clean up old fingerprints to free space
- Provide troubleshooting information

Usage:
    python3 manage_fingerprint_db.py --status    # Check database status
    python3 manage_fingerprint_db.py --list      # List users and fingerprints
    python3 manage_fingerprint_db.py --cleanup   # Interactive cleanup
    python3 manage_fingerprint_db.py --clear-all # Clear all fingerprints (dangerous!)
"""

import sys
import os
import argparse
import logging

# Add the validitysensor module to the path
sys.path.insert(0, '/usr/lib/python3.13/site-packages')

try:
    from validitysensor.init import init_all
    from validitysensor.db import Db
    from validitysensor.util import DatabaseFullException, DeviceStorageException
    from validitysensor.tls import tls
    
    def setup_logging():
        """Setup logging to suppress debug messages."""
        logging.basicConfig(level=logging.WARNING)
        
    def check_database_status():
        """Check and display database storage status."""
        print("=== Fingerprint Database Status ===")
        try:
            init_all()
            db = Db()
            
            # Get database info
            db_info = db.db_info()
            total_mb = db_info.total / 1024 / 1024
            used_mb = db_info.used / 1024 / 1024
            free_mb = db_info.free / 1024 / 1024
            usage_pct = (db_info.used / db_info.total * 100) if db_info.total > 0 else 0
            
            print(f"Total space: {total_mb:.2f} MB ({db_info.total} bytes)")
            print(f"Used space:  {used_mb:.2f} MB ({db_info.used} bytes)")
            print(f"Free space:  {free_mb:.2f} MB ({db_info.free} bytes)")
            print(f"Records:     {db_info.records}")
            print(f"Usage:       {usage_pct:.1f}%")
            
            # Warn about low space
            if db_info.free < 10000:  # Less than 10KB free
                print("\n⚠️  WARNING: Very low free space! Database may be full.")
                print("   Consider running cleanup to remove old fingerprints.")
            elif db_info.free < 50000:  # Less than 50KB free  
                print("\n⚠️  CAUTION: Low free space remaining.")
            else:
                print("\n✅ Database has sufficient free space.")
                
        except Exception as e:
            print(f"❌ Error checking database status: {e}")
            return False
        
        return True
    
    def list_users_and_fingerprints():
        """List all users and their fingerprints."""
        print("=== Users and Fingerprints ===")
        try:
            init_all()
            db = Db()
            
            # Get user storage info
            stg = db.get_user_storage(name='StgWindsor')
            print(f"Storage: {stg.name} (ID: {stg.dbid})")
            print(f"Users found: {len(stg.users)}")
            
            if len(stg.users) == 0:
                print("No users found in database.")
                return True
            
            # List all users and their fingerprints
            for i, user_info in enumerate(stg.users):
                try:
                    user = db.get_user(user_info['dbid'])
                    print(f"\nUser {i+1}:")
                    print(f"  Database ID: {user.dbid}")
                    print(f"  Identity: {user.identity}")
                    print(f"  Fingerprints: {len(user.fingers)}")
                    
                    for j, finger in enumerate(user.fingers):
                        print(f"    Fingerprint {j+1}:")
                        print(f"      ID: {finger['dbid']}")
                        print(f"      Subtype: {finger['subtype']}")
                        print(f"      Storage: {finger['storage']}")
                        print(f"      Size: {finger['valueSize']} bytes")
                        
                except Exception as e:
                    print(f"  Error reading user {user_info['dbid']}: {e}")
                    
        except Exception as e:
            print(f"❌ Error listing users: {e}")
            return False
        
        return True
    
    def interactive_cleanup():
        """Interactive cleanup of fingerprints."""
        print("=== Interactive Database Cleanup ===")
        try:
            init_all()
            db = Db()
            
            # Show current status
            db_info = db.db_info()
            print(f"Current free space: {db_info.free} bytes ({db_info.free/1024:.1f} KB)")
            
            stg = db.get_user_storage(name='StgWindsor')
            if len(stg.users) == 0:
                print("No users found - database is already clean.")
                return True
            
            print(f"Found {len(stg.users)} users with fingerprints.")
            
            # List users for selection
            print("\nUsers:")
            for i, user_info in enumerate(stg.users):
                try:
                    user = db.get_user(user_info['dbid'])
                    print(f"  {i+1}. {user.identity} ({len(user.fingers)} fingerprints)")
                except:
                    print(f"  {i+1}. User ID {user_info['dbid']} (error reading details)")
            
            print("\nCleanup options:")
            print("  1. Delete specific user")
            print("  2. Delete all users and fingerprints")
            print("  3. Cancel")
            
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice == '1':
                user_num = input(f"Enter user number to delete (1-{len(stg.users)}): ").strip()
                try:
                    user_idx = int(user_num) - 1
                    if 0 <= user_idx < len(stg.users):
                        user_info = stg.users[user_idx]
                        user = db.get_user(user_info['dbid'])
                        
                        confirm = input(f"Delete user '{user.identity}' and all their fingerprints? (yes/no): ")
                        if confirm.lower() in ['yes', 'y']:
                            db.del_record(user.dbid)
                            print(f"✅ Deleted user '{user.identity}'")
                        else:
                            print("Cancelled.")
                    else:
                        print("Invalid user number.")
                except (ValueError, IndexError):
                    print("Invalid input.")
                    
            elif choice == '2':
                confirm = input("⚠️  Delete ALL users and fingerprints? This cannot be undone! (yes/no): ")
                if confirm.lower() in ['yes', 'y']:
                    for user_info in stg.users:
                        try:
                            db.del_record(user_info['dbid'])
                            print(f"Deleted user ID {user_info['dbid']}")
                        except Exception as e:
                            print(f"Error deleting user {user_info['dbid']}: {e}")
                    print("✅ Database cleanup completed.")
                else:
                    print("Cancelled.")
                    
            elif choice == '3':
                print("Cancelled.")
            else:
                print("Invalid choice.")
            
            # Show final status
            db_info = db.db_info()
            print(f"\nFinal free space: {db_info.free} bytes ({db_info.free/1024:.1f} KB)")
            
        except Exception as e:
            print(f"❌ Error during cleanup: {e}")
            return False
        
        return True
    
    def clear_all_fingerprints():
        """Clear all fingerprints (dangerous operation)."""
        print("=== Clear All Fingerprints ===")
        print("⚠️  WARNING: This will delete ALL fingerprints from the database!")
        print("This operation cannot be undone.")
        
        confirm1 = input("Are you sure you want to continue? (yes/no): ")
        if confirm1.lower() not in ['yes', 'y']:
            print("Operation cancelled.")
            return True
        
        confirm2 = input("Type 'DELETE ALL' to confirm: ")
        if confirm2 != 'DELETE ALL':
            print("Operation cancelled.")
            return True
        
        try:
            init_all()
            db = Db()
            
            stg = db.get_user_storage(name='StgWindsor')
            deleted_count = 0
            
            for user_info in stg.users:
                try:
                    db.del_record(user_info['dbid'])
                    deleted_count += 1
                except Exception as e:
                    print(f"Error deleting user {user_info['dbid']}: {e}")
            
            print(f"✅ Deleted {deleted_count} users and all their fingerprints.")
            
            # Show final status
            db_info = db.db_info()
            print(f"Free space after cleanup: {db_info.free} bytes ({db_info.free/1024:.1f} KB)")
            
        except Exception as e:
            print(f"❌ Error during cleanup: {e}")
            return False
        
        return True
    
    def main():
        parser = argparse.ArgumentParser(
            description='Manage fingerprint database for python-validity',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=__doc__
        )
        
        parser.add_argument('--status', action='store_true',
                          help='Check database status and storage usage')
        parser.add_argument('--list', action='store_true', 
                          help='List all users and fingerprints')
        parser.add_argument('--cleanup', action='store_true',
                          help='Interactive cleanup of fingerprints')
        parser.add_argument('--clear-all', action='store_true',
                          help='Clear all fingerprints (dangerous!)')
        
        args = parser.parse_args()
        
        # Setup logging to reduce noise
        setup_logging()
        
        if not any([args.status, args.list, args.cleanup, args.clear_all]):
            # Default action if no arguments provided
            print("Fingerprint Database Management Utility")
            print("=" * 40)
            check_database_status()
            print()
            list_users_and_fingerprints()
            return
        
        success = True
        
        if args.status:
            success &= check_database_status()
            
        if args.list:
            if args.status:
                print()
            success &= list_users_and_fingerprints()
            
        if args.cleanup:
            if args.status or args.list:
                print()
            success &= interactive_cleanup()
            
        if args.clear_all:
            if args.status or args.list or args.cleanup:
                print()
            success &= clear_all_fingerprints()
        
        if not success:
            sys.exit(1)

    if __name__ == "__main__":
        main()

except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Make sure the python-validity package is properly installed.")
    print("You may need to run this script as root or with appropriate permissions.")
    sys.exit(1)
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    sys.exit(1)
