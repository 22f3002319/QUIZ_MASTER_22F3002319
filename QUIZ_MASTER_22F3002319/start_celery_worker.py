#!/usr/bin/env python3
"""
Celery Worker Starter
This script starts the Celery worker for background email tasks.
"""

import sys
import os
import subprocess
import time

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_redis():
    """Check if Redis is running"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        print("✅ Redis is running")
        return True
    except Exception as e:
        print(f"❌ Redis is not running: {e}")
        return False

def start_celery_worker():
    """Start the Celery worker"""
    try:
        print("🚀 Starting Celery worker...")
        
        # Get the path to python executable in virtual environment
        venv_python = os.path.join(os.getcwd(), '.venv', 'Scripts', 'python.exe')
        
        if not os.path.exists(venv_python):
            print("❌ Virtual environment not found!")
            print("Please activate your virtual environment first.")
            return False
        
        # Start Celery worker
        cmd = [
            venv_python, '-m', 'celery', '-A', 'celery_config', 'worker',
            '--loglevel=info', '--pool=solo'
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        
        # Start the process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print("✅ Celery worker started successfully!")
        print("The worker is now running in the background.")
        print("You can now export CSV data and receive emails.")
        print("\nTo stop the worker, press Ctrl+C")
        
        # Wait for a moment to see if it starts successfully
        time.sleep(3)
        
        # Check if process is still running
        if process.poll() is None:
            print("✅ Worker is running properly")
            return True
        else:
            stdout, stderr = process.communicate()
            print(f"❌ Worker failed to start:")
            print(f"STDOUT: {stdout}")
            print(f"STDERR: {stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to start Celery worker: {e}")
        return False

def main():
    print("🔧 Celery Worker Starter")
    print("=" * 30)
    
    # Check Redis first
    if not check_redis():
        print("\n⚠️  Please start Redis first:")
        print("1. Open a new terminal")
        print("2. Run: redis-server")
        print("3. Then run this script again")
        return
    
    # Start Celery worker
    success = start_celery_worker()
    
    if success:
        print("\n🎉 Setup complete!")
        print("Now you can:")
        print("1. Export CSV data from the web interface")
        print("2. Check emails in Mailhog: http://localhost:8025")
        print("3. The worker will process email tasks in the background")
    else:
        print("\n❌ Failed to start Celery worker")
        print("Check the error messages above.")

if __name__ == "__main__":
    main() 