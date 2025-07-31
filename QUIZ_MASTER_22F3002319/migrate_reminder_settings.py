#!/usr/bin/env python3
"""
Migration Script for Reminder Settings
This script adds the ReminderSettings table to the database.
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def migrate_reminder_settings():
    """Add ReminderSettings table and create default settings"""
    try:
        from app import app, db
        from models import ReminderSettings
        
        with app.app_context():
            print("🔧 Starting Reminder Settings Migration...")
            
            # Create the ReminderSettings table
            print("📋 Creating ReminderSettings table...")
            db.create_all()
            
            # Check if settings already exist
            existing_settings = ReminderSettings.query.first()
            if existing_settings:
                print("✅ ReminderSettings table already exists with data")
                print(f"   Daily reminders: {existing_settings.daily_reminder_hour}:{existing_settings.daily_reminder_minute:02d}")
                print(f"   Monthly reminders: Day {existing_settings.monthly_reminder_day} at {existing_settings.monthly_reminder_hour}:{existing_settings.monthly_reminder_minute:02d}")
                print(f"   Daily enabled: {existing_settings.daily_reminders_enabled}")
                print(f"   Monthly enabled: {existing_settings.monthly_reminders_enabled}")
            else:
                # Create default settings
                print("📝 Creating default reminder settings...")
                default_settings = ReminderSettings(
                    daily_reminder_hour=18,  # 6 PM
                    daily_reminder_minute=0,
                    monthly_reminder_day=1,  # 1st day of month
                    monthly_reminder_hour=9,  # 9 AM
                    monthly_reminder_minute=0,
                    daily_reminders_enabled=True,
                    monthly_reminders_enabled=True
                )
                
                db.session.add(default_settings)
                db.session.commit()
                
                print("✅ Default reminder settings created successfully!")
                print("   Daily reminders: 18:00 (6 PM)")
                print("   Monthly reminders: Day 1 at 09:00 (9 AM)")
                print("   Both reminder types are enabled by default")
            
            print("\n🎉 Reminder Settings migration completed successfully!")
            print("\n📋 Next steps:")
            print("1. Restart your Flask application")
            print("2. Access the admin dashboard")
            print("3. Click on 'Reminder Settings' in the navigation")
            print("4. Configure your preferred reminder schedules")
            print("5. Make sure Celery Beat is running for scheduled tasks")
            
            return True
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False

def main():
    print("🔄 Reminder Settings Migration Tool")
    print("=" * 40)
    
    success = migrate_reminder_settings()
    
    if success:
        print("\n✅ Migration completed successfully!")
    else:
        print("\n❌ Migration failed!")
        print("Please check the error messages above.")

if __name__ == "__main__":
    main() 