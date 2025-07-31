from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField, SelectField, IntegerField, EmailField, BooleanField
from wtforms.validators import DataRequired, Length, Email, NumberRange, EqualTo, ValidationError, Optional, Regexp
from datetime import date

class UserRegistrationForm(FlaskForm):
    username = EmailField('Email Address', validators=[
        DataRequired(message="Email is required."),
        Email(message="Please enter a valid email address."),
        Length(max=150, message="Email must be less than 150 characters.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password."),
        EqualTo('password', message='Passwords must match.')
    ])
    full_name = StringField('Full Name', validators=[
        DataRequired(message="Full name is required."),
        Length(min=2, max=150, message="Full name must be between 2 and 150 characters.")
    ])
    qualification = StringField('Qualification', validators=[
        DataRequired(message="Qualification is required."),
        Length(max=150, message="Qualification must be less than 150 characters.")
    ])
    dob = DateField('Date of Birth', validators=[DataRequired(message="Date of birth is required.")])

    def validate_dob(self, field):
        if field.data > date.today():
            raise ValidationError("Date of birth cannot be in the future.")
        
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class SubjectForm(FlaskForm):
    name = StringField('Subject Name', validators=[
        DataRequired(message="Subject name is required."),
        Length(min=2, max=150, message="Subject name must be between 2 and 150 characters.")
    ])
    description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=1000, message="Description must be less than 1000 characters.")
    ])
    submit = SubmitField('Add Subject')

class ChapterForm(FlaskForm):
    name = StringField('Chapter Name', validators=[
        DataRequired(message="Chapter name is required."),
        Length(min=2, max=150, message="Chapter name must be between 2 and 150 characters.")
    ])
    description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=1000, message="Description must be less than 1000 characters.")
    ])
    subject_id = SelectField('Subject', coerce=int, validators=[DataRequired(message="Please select a subject.")])
    submit = SubmitField('Add Chapter')

    def __init__(self, *args, **kwargs):
        super(ChapterForm, self).__init__(*args, **kwargs)
        from models import Subject
        self.subject_id.choices = [(s.id, s.name) for s in Subject.query.all()]

class QuizForm(FlaskForm):
    time_duration = IntegerField('Time Duration (minutes)', 
                               validators=[
                                   DataRequired(message="Time duration is required."),
                                   NumberRange(min=1, max=180, message="Duration must be between 1 and 180 minutes.")
                               ])
    remarks = TextAreaField('Quiz Title/Description', 
                          validators=[
                              DataRequired(message="Quiz title is required."),
                              Length(min=3, max=200, message="Quiz title must be between 3 and 200 characters.")
                          ])

class QuestionForm(FlaskForm):
    question_statement = TextAreaField('Question', validators=[
        DataRequired(message="Question statement is required."),
        Length(min=10, message="Question must be at least 10 characters long.")
    ])
    option1 = StringField('Option 1', validators=[
        DataRequired(message="Option 1 is required."),
        Length(min=1, max=150, message="Option must be between 1 and 150 characters.")
    ])
    option2 = StringField('Option 2', validators=[
        DataRequired(message="Option 2 is required."),
        Length(min=1, max=150, message="Option must be between 1 and 150 characters.")
    ])
    option3 = StringField('Option 3', validators=[
        DataRequired(message="Option 3 is required."),
        Length(min=1, max=150, message="Option must be between 1 and 150 characters.")
    ])
    option4 = StringField('Option 4', validators=[
        DataRequired(message="Option 4 is required."),
        Length(min=1, max=150, message="Option must be between 1 and 150 characters.")
    ])
    correct_option = SelectField('Correct Option', 
                               choices=[
                                   ('option1', 'Option 1'), 
                                   ('option2', 'Option 2'), 
                                   ('option3', 'Option 3'), 
                                   ('option4', 'Option 4')
                               ],
                               validators=[DataRequired(message="Please select the correct option.")])
    submit = SubmitField('Add Question')

    def validate_correct_option(self, field):
        """Validate that the correct option matches one of the provided options"""
        correct = field.data
        options = [self.option1.data, self.option2.data, self.option3.data, self.option4.data]
        
        # Check for duplicate options
        if len(set(options)) != len(options):
            raise ValidationError("All options must be unique.")
        
        # Validate that correct option is selected
        if correct not in ['option1', 'option2', 'option3', 'option4']:
            raise ValidationError("Please select a valid correct option.")

class UserProfileForm(FlaskForm):
    email = EmailField('Email', validators=[
        DataRequired(message="Email is required."),
        Email(message="Please enter a valid email address."),
        Length(max=150, message="Email must be less than 150 characters.")
    ])
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=150)])
    qualification = StringField('Qualification', validators=[DataRequired(), Length(min=2, max=150)])
    date_of_birth = DateField('Date of Birth', validators=[DataRequired()])
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[
        Optional(),
        EqualTo('new_password', message='Passwords must match.')
    ])

    def validate_date_of_birth(self, field):
        if field.data > date.today():
            raise ValidationError('Date of birth cannot be in the future.')

    def validate_current_password(self, field):
        if self.new_password.data and not field.data:
            raise ValidationError("Current password is required to change password.")

class ReminderSettingsForm(FlaskForm):
    daily_reminder_hour = IntegerField('Daily Reminder Hour', validators=[
        DataRequired(message="Hour is required."),
        NumberRange(min=0, max=23, message="Hour must be between 0 and 23.")
    ])
    daily_reminder_minute = IntegerField('Daily Reminder Minute', validators=[
        DataRequired(message="Minute is required."),
        NumberRange(min=0, max=59, message="Minute must be between 0 and 59.")
    ])
    monthly_reminder_day = IntegerField('Monthly Reminder Day', validators=[
        DataRequired(message="Day is required."),
        NumberRange(min=1, max=31, message="Day must be between 1 and 31.")
    ])
    monthly_reminder_hour = IntegerField('Monthly Reminder Hour', validators=[
        DataRequired(message="Hour is required."),
        NumberRange(min=0, max=23, message="Hour must be between 0 and 23.")
    ])
    monthly_reminder_minute = IntegerField('Monthly Reminder Minute', validators=[
        DataRequired(message="Minute is required."),
        NumberRange(min=0, max=59, message="Minute must be between 0 and 59.")
    ])
    daily_reminders_enabled = BooleanField('Enable Daily Reminders')
    monthly_reminders_enabled = BooleanField('Enable Monthly Reminders')
    submit = SubmitField('Save Settings')