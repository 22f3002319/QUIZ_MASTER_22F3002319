from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password = db.Column(db.String(150), nullable=False)
    full_name = db.Column(db.String(150), nullable=False, index=True)
    qualification = db.Column(db.String(150), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, index=True)
    quiz_attempts = db.relationship('QuizAttempt', backref='user', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.username}>'

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, index=True)
    description = db.Column(db.Text)
    chapters = db.relationship('Chapter', backref='subject', lazy=True, cascade='all, delete-orphan')

class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, index=True)
    description = db.Column(db.Text)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id', ondelete='CASCADE'), nullable=False, index=True)
    quizzes = db.relationship('Quiz', backref='chapter', lazy=True, cascade='all, delete-orphan')

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id', ondelete='CASCADE'), nullable=False, index=True)
    date_of_quiz = db.Column(db.Date, nullable=True)  # Date when quiz is scheduled
    time_duration = db.Column(db.Integer, nullable=False)  # Duration in minutes
    remarks = db.Column(db.Text, nullable=False, default='')  # Make remarks non-nullable with default
    questions = db.relationship('Question', backref='quiz', lazy=True, cascade='all, delete-orphan')
    attempts = db.relationship('QuizAttempt', backref='quiz', lazy=True, cascade='all, delete-orphan')

    def __init__(self, **kwargs):
        super(Quiz, self).__init__(**kwargs)
        if self.remarks is None:
            self.remarks = ''

    def get_duration_minutes(self):
        """Return duration in minutes (already stored as minutes)"""
        return self.time_duration or 0

    def get_duration_formatted(self):
        """Convert minutes to HH:MM format for display"""
        if self.time_duration:
            hours = self.time_duration // 60
            minutes = self.time_duration % 60
            return f"{hours:02d}:{minutes:02d}"
        return "00:00"

    def set_duration_from_string(self, time_str):
        """Set duration from HH:MM string format"""
        if time_str and ':' in time_str:
            try:
                hours, minutes = map(int, time_str.split(':'))
                self.time_duration = hours * 60 + minutes
            except ValueError:
                self.time_duration = 30  # Default 30 minutes
        else:
            self.time_duration = 30  # Default 30 minutes

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False, index=True)
    question_statement = db.Column(db.Text, nullable=False, index=True)
    option1 = db.Column(db.String(150), nullable=False)
    option2 = db.Column(db.String(150), nullable=False)
    option3 = db.Column(db.String(150), nullable=False)
    option4 = db.Column(db.String(150), nullable=False)
    correct_option = db.Column(db.String(150), nullable=False)

class QuizAttempt(db.Model):
    __tablename__ = 'quiz_attempt'
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False)  # Total score achieved
    total_questions = db.Column(db.Integer, nullable=False)
    attempt_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class ReminderSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    daily_reminder_hour = db.Column(db.Integer, default=18, nullable=False)  # Default 6 PM
    daily_reminder_minute = db.Column(db.Integer, default=0, nullable=False)
    monthly_reminder_day = db.Column(db.Integer, default=1, nullable=False)  # Default 1st day
    monthly_reminder_hour = db.Column(db.Integer, default=9, nullable=False)  # Default 9 AM
    monthly_reminder_minute = db.Column(db.Integer, default=0, nullable=False)
    daily_reminders_enabled = db.Column(db.Boolean, default=True, nullable=False)
    monthly_reminders_enabled = db.Column(db.Boolean, default=True, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<ReminderSettings daily={self.daily_reminder_hour}:{self.daily_reminder_minute} monthly={self.monthly_reminder_day} {self.monthly_reminder_hour}:{self.monthly_reminder_minute}>'