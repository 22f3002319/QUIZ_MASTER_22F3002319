from celery import Celery
from celery.schedules import crontab

def create_celery_app():
    """Create and configure Celery app"""
    celery = Celery('quiz_master')
    
    # Configure Celery with environment variables
    import os
    broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    result_backend = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    
    celery.conf.update(
        broker_url=broker_url,
        result_backend=result_backend,
        timezone='UTC',
        enable_utc=True,
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        task_track_started=True,
        task_time_limit=30 * 60,  # 30 minutes
        task_soft_time_limit=25 * 60,  # 25 minutes
        include=['tasks']  # Include tasks module
    )
    
    return celery

# Create the celery instance
celery = create_celery_app()

# Import and apply the ContextTask from app.py
from app import ContextTask
celery.Task = ContextTask

# Scheduled tasks configuration
@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    # This will be updated dynamically based on database settings
    update_scheduled_tasks(sender)

def update_scheduled_tasks(sender):
    """Update scheduled tasks based on database settings"""
    try:
        from app import app
        from models import ReminderSettings
        
        with app.app_context():
            settings = ReminderSettings.query.first()
            if not settings:
                # Use default settings if none exist
                settings = ReminderSettings()
            
            # Clear existing tasks
            sender.conf.beat_schedule = {}
            
            # Add daily reminders if enabled
            if settings.daily_reminders_enabled:
                sender.add_periodic_task(
                    crontab(hour=settings.daily_reminder_hour, minute=settings.daily_reminder_minute),
                    sender.signature('tasks.send_daily_reminders'),
                    name='daily-reminders'
                )
            
            # Add monthly reports if enabled
            if settings.monthly_reminders_enabled:
                sender.add_periodic_task(
                    crontab(day_of_month=settings.monthly_reminder_day, 
                           hour=settings.monthly_reminder_hour, 
                           minute=settings.monthly_reminder_minute),
                    sender.signature('tasks.send_monthly_reports'),
                    name='monthly-reports'
                )
                
    except Exception as e:
        # Fallback to default settings if database is not available
        sender.add_periodic_task(
            crontab(hour=18, minute=0),  # 6 PM daily
            sender.signature('tasks.send_daily_reminders'),
            name='daily-reminders'
        )
        
        sender.add_periodic_task(
            crontab(day_of_month=1, hour=9, minute=0),  # 1st day, 9 AM
            sender.signature('tasks.send_monthly_reports'),
            name='monthly-reports'
        )