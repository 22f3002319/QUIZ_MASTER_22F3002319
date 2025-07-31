#!/usr/bin/env python3
"""
Quiz Master Startup Script
This script helps you start all the required services for the Quiz Master application.
"""

import os
import sys
import subprocess
import time
import signal
import platform
from pathlib import Path

def check_redis():
    """Check if Redis is running"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        print("✅ Redis is running")
        return True
    except:
        print("❌ Redis is not running")
        return False

def start_redis():
    """Start Redis server"""
    system = platform.system().lower()
    
    if system == "windows":
        print("Please start Redis manually on Windows:")
        print("1. Download Redis for Windows from https://github.com/microsoftarchive/redis/releases")
        print("2. Run: redis-server")
        return False
    elif system == "darwin":  # macOS
        try:
            subprocess.run(["brew", "services", "start", "redis"], check=True)
            print("✅ Redis started via Homebrew")
            return True
        except:
            print("❌ Failed to start Redis via Homebrew")
            return False
    else:  # Linux
        try:
            subprocess.run(["sudo", "systemctl", "start", "redis"], check=True)
            print("✅ Redis started via systemctl")
            return True
        except:
            print("❌ Failed to start Redis via systemctl")
            return False

def start_celery():
    """Start Celery worker"""
    try:
        # Start Celery worker in background
        celery_cmd = [
            sys.executable, "-m", "celery", "-A", "celery_config", "worker",
            "--loglevel=info", "--concurrency=1"
        ]
        
        print("Starting Celery worker...")
        celery_process = subprocess.Popen(
            celery_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait a moment to see if it starts successfully
        time.sleep(3)
        if celery_process.poll() is None:
            print("✅ Celery worker started")
            return celery_process
        else:
            print("❌ Failed to start Celery worker")
            return None
    except Exception as e:
        print(f"❌ Error starting Celery: {e}")
        return None

def start_celery_beat():
    """Start Celery beat scheduler"""
    try:
        # Start Celery beat in background
        beat_cmd = [
            sys.executable, "-m", "celery", "-A", "celery_config", "beat",
            "--loglevel=info"
        ]
        
        print("Starting Celery beat scheduler...")
        beat_process = subprocess.Popen(
            beat_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait a moment to see if it starts successfully
        time.sleep(3)
        if beat_process.poll() is None:
            print("✅ Celery beat scheduler started")
            return beat_process
        else:
            print("❌ Failed to start Celery beat scheduler")
            return None
    except Exception as e:
        print(f"❌ Error starting Celery beat: {e}")
        return None

def start_flask():
    """Start Flask application"""
    try:
        print("Starting Flask application...")
        flask_cmd = [sys.executable, "app.py"]
        flask_process = subprocess.Popen(flask_cmd)
        print("✅ Flask application started")
        return flask_process
    except Exception as e:
        print(f"❌ Error starting Flask: {e}")
        return None

def cleanup(processes):
    """Cleanup function to stop all processes"""
    print("\n🛑 Stopping all services...")
    for process in processes:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

def main():
    print("🚀 Quiz Master Startup Script")
    print("=" * 40)
    
    # Check if we're in the right directory
    if not Path("app.py").exists():
        print("❌ Please run this script from the QUIZ_MASTER_22F3002319 directory")
        sys.exit(1)
    
    processes = []
    
    try:
        # Check and start Redis
        if not check_redis():
            if not start_redis():
                print("❌ Cannot start Redis. Please start it manually.")
                sys.exit(1)
            time.sleep(2)  # Wait for Redis to start
        
        # Start Celery worker
        celery_process = start_celery()
        if celery_process:
            processes.append(celery_process)
        else:
            print("❌ Cannot start Celery worker.")
            sys.exit(1)
        
        # Start Celery beat scheduler
        beat_process = start_celery_beat()
        if beat_process:
            processes.append(beat_process)
        else:
            print("⚠️  Celery beat scheduler failed to start. Scheduled tasks won't work.")
        
        # Start Flask application
        flask_process = start_flask()
        if flask_process:
            processes.append(flask_process)
        else:
            print("❌ Cannot start Flask application.")
            sys.exit(1)
        
        print("\n🎉 All services started successfully!")
        print("📱 Flask application: http://localhost:5000")
        print("👤 Admin login: admin@example.com / admin123")
        print("\nPress Ctrl+C to stop all services")
        
        # Wait for user to stop
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Received interrupt signal")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        cleanup(processes)
        print("✅ All services stopped")

if __name__ == "__main__":
    main()