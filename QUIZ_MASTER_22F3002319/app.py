from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, send_file, make_response
from forms import UserRegistrationForm, LoginForm, SubjectForm, ChapterForm, QuizForm, QuestionForm, UserProfileForm
from models import db, User, Subject, Chapter, Quiz, Question, QuizAttempt
from flask_login import login_required, login_user, logout_user, current_user, LoginManager
from datetime import datetime, date
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField, IntegerField, SelectField
from wtforms.validators import DataRequired, NumberRange
import logging
import os
import argparse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from io import BytesIO
from config import Config
from flask_mail import Mail
from flask_caching import Cache
from celery_config import celery
from tasks import export_user_quiz_data_csv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Load environment variables at startup
# load_env_file() # This line is removed as per the new_code

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.mkdir('logs')

# Configure logging with Windows-compatible handler
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

# Use a simple file handler to avoid Windows file locking issues
try:
    file_handler = logging.FileHandler('logs/quiz_master.log', mode='a', encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
except Exception as e:
    # Fallback to console logging if file handler fails
    file_handler = logging.StreamHandler()
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

# Configure application logger
app = Flask(__name__)
app.config.from_object(Config)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Quiz Master startup')

# Initialize extensions
db.init_app(app)
mail = Mail(app)

# Initialize cache with fallback
try:
    cache = Cache(app)
    app.logger.info('Redis cache initialized successfully')
except Exception as e:
    app.logger.warning(f'Redis cache initialization failed: {str(e)}. Using simple cache.')
    app.config['CACHE_TYPE'] = 'simple'
    cache = Cache(app)

# Initialize CSRF protection
csrf = CSRFProtect()
csrf.init_app(app)

# Initialize rate limiting with fallback
try:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=app.config.get('RATELIMIT_STORAGE_URL', 'redis://localhost:6379/0')
    )
    app.logger.info('Rate limiter initialized with Redis')
except Exception as e:
    app.logger.warning(f'Rate limiter Redis initialization failed: {str(e)}. Using memory storage.')
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )

# Initialize Celery with fallback
try:
    celery.conf.update(
        broker_url=app.config.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
        result_backend=app.config.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    )
    app.logger.info('Celery initialized with Redis')
except Exception as e:
    app.logger.warning(f'Celery Redis initialization failed: {str(e)}. Using memory broker.')
    celery.conf.update(
        broker_url='memory://',
        result_backend='rpc://'
    )

class ContextTask(celery.Task):
    def __call__(self, *args, **kwargs):
        with app.app_context():
            return self.run(*args, **kwargs)

celery.Task = ContextTask

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
    )
    return response

# Create tables and admin user
with app.app_context():
    # Create all tables if they don't exist
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(username=app.config['ADMIN_EMAIL']).first()
    if not admin:
        # Create admin user with proper password hashing
        try:
            admin = User(
                username=app.config['ADMIN_EMAIL'],
                password=generate_password_hash(app.config['ADMIN_PASSWORD']),
                full_name=app.config['ADMIN_FULL_NAME'],
                qualification='Admin',
                dob=datetime.now().date(),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            app.logger.info('Admin user created successfully')
        except IntegrityError:
            db.session.rollback()
            app.logger.warning('Admin user already exists')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating admin user: {str(e)}')

# Cache invalidation functions
def invalidate_user_cache(user_id):
    """Invalidate user-specific cache entries"""
    try:
        cache.delete(f'user_dashboard_{user_id}')
        cache.delete(f'user_summary_{user_id}')
        cache.delete(f'user_scores_{user_id}')
        app.logger.info(f'Cache invalidated for user {user_id}')
    except Exception as e:
        app.logger.error(f'Error invalidating cache for user {user_id}: {str(e)}')

def invalidate_admin_cache():
    """Invalidate admin-specific cache entries"""
    try:
        # Clear all cache entries for admin routes
        cache.clear()
        app.logger.info('Admin cache invalidated - all cache cleared')
    except Exception as e:
        app.logger.error(f'Error invalidating admin cache: {str(e)}')

def invalidate_global_cache():
    """Invalidate global cache entries"""
    try:
        # Clear all cache entries
        cache.clear()
        app.logger.info('Global cache invalidated - all cache cleared')
    except Exception as e:
        app.logger.error(f'Error invalidating global cache: {str(e)}')

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            if user.is_admin:  # Use role check instead of email comparison
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")  # Rate limit registration attempts
def register():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
    
    form = UserRegistrationForm()
    if form.validate_on_submit():
        try:
            # Check if user already exists
            if User.query.filter_by(username=form.username.data).first():
                flash('This email address is already registered. Please use a different email or login.', 'danger')
                return render_template('register.html', form=form, today_date=date.today().isoformat())
            
            new_user = User(
                username=form.username.data,
                password=generate_password_hash(form.password.data),
                full_name=form.full_name.data,
                qualification=form.qualification.data,
                dob=form.dob.data
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            app.logger.error(f'Registration error: {str(e)}')
    
    return render_template('register.html', form=form, today_date=date.today().isoformat())

@app.route('/logout')
@login_required
def logout_page():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    active_tab = request.args.get('tab', 'subject')
    # Use eager loading to avoid N+1 queries
    subjects = Subject.query.options(
        joinedload(Subject.chapters)
    ).all()
    users = User.query.all()
    
    # Calculate counts
    total_chapters = sum(len(subject.chapters) for subject in subjects)
    total_quizzes = sum(len(chapter.quizzes) for subject in subjects for chapter in subject.chapters)
    
    return render_template('admin_dashboard.html', 
                         subjects=subjects, 
                         users=users, 
                         active_tab=active_tab,
                         total_chapters=total_chapters,
                         total_quizzes=total_quizzes)

@app.route('/quiz_management')
@login_required
def quiz_management():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Use eager loading to avoid N+1 queries
        subjects = Subject.query.options(
            joinedload(Subject.chapters).joinedload(Chapter.quizzes).joinedload(Quiz.questions)
        ).all()
        
        return render_template('quiz_management.html', subjects=subjects)
    except Exception as e:
        app.logger.error(f'Quiz Management Error: {str(e)}')
        flash('An error occurred while loading quiz management.', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/manage_questions/<int:quiz_id>')
@login_required
def manage_questions(quiz_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('manage_questions.html', quiz=quiz)

@app.route('/add_quiz/<int:chapter_id>', methods=['GET', 'POST'])
@login_required
@limiter.limit("30 per hour")  # Rate limit quiz creation
def add_quiz(chapter_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    try:
        chapter = Chapter.query.get_or_404(chapter_id)
        form = QuizForm()
        
        if form.validate_on_submit():
            quiz = Quiz(
                time_duration=form.time_duration.data,
                remarks=form.remarks.data,
                chapter_id=chapter_id
            )
            db.session.add(quiz)
            try:
                db.session.commit()
                # Invalidate cache after successful quiz creation
                invalidate_admin_cache()
                invalidate_global_cache()
                flash('Quiz added successfully.', 'success')
                return redirect(url_for('quiz_management'))
            except IntegrityError as e:
                db.session.rollback()
                app.logger.error(f'Database integrity error: {str(e)}')
                flash('A quiz with this name already exists in this chapter.', 'danger')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Error adding quiz: {str(e)}')
                flash(f'An error occurred while adding the quiz: {str(e)}', 'danger')
        elif form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    except Exception as e:
        app.logger.error(f'Error in add_quiz route: {str(e)}')
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('quiz_management'))
    
    return render_template('add_quiz.html', form=form, chapter=chapter)

@app.route('/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def edit_quiz(quiz_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    try:
        quiz = Quiz.query.get_or_404(quiz_id)
        form = QuizForm(obj=quiz)
        
        if form.validate_on_submit():
            quiz.time_duration = form.time_duration.data
            quiz.remarks = form.remarks.data
            try:
                db.session.commit()
                # Invalidate cache after successful quiz update
                invalidate_admin_cache()
                invalidate_global_cache()
                flash('Quiz updated successfully.', 'success')
                return redirect(url_for('quiz_management'))
            except IntegrityError:
                db.session.rollback()
                flash('A quiz with this name already exists in this chapter.', 'danger')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Error updating quiz: {str(e)}')
                flash('An error occurred while updating the quiz. Please try again.', 'danger')
        elif form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    except Exception as e:
        app.logger.error(f'Error in edit_quiz route: {str(e)}')
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('quiz_management'))
    
    return render_template('edit_quiz.html', form=form, quiz=quiz)

@app.route('/delete_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def delete_quiz(quiz_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    try:
        quiz = Quiz.query.get_or_404(quiz_id)
        try:
            # Delete all questions and attempts associated with this quiz
            Question.query.filter_by(quiz_id=quiz_id).delete()
            QuizAttempt.query.filter_by(quiz_id=quiz_id).delete()
            db.session.delete(quiz)
            db.session.commit()
            # Invalidate cache after successful quiz deletion
            invalidate_admin_cache()
            invalidate_global_cache()
            flash('Quiz deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error deleting quiz: {str(e)}')
            flash('An error occurred while deleting the quiz. Please try again.', 'danger')
    except Exception as e:
        app.logger.error(f'Error in delete_quiz route: {str(e)}')
        flash('An error occurred. Please try again.', 'danger')
    
    return redirect(url_for('quiz_management'))

@app.route('/add_question/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
@limiter.limit("50 per hour")  # Rate limit question creation
def add_question(quiz_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    try:
        quiz = Quiz.query.get_or_404(quiz_id)
        form = QuestionForm()
        
        if form.validate_on_submit():
            try:
                # Get the actual option value based on the selected option
                selected_option = form.correct_option.data
                correct_answer = getattr(form, selected_option).data
                
                question = Question(
                    question_statement=form.question_statement.data,
                    option1=form.option1.data,
                    option2=form.option2.data,
                    option3=form.option3.data,
                    option4=form.option4.data,
                    correct_option=correct_answer,  # Store the actual answer text
                    quiz_id=quiz_id
                )
                db.session.add(question)
                db.session.commit()
                # Invalidate cache after successful question creation
                invalidate_admin_cache()
                invalidate_global_cache()
                flash('Question added successfully.', 'success')
                return redirect(url_for('manage_questions', quiz_id=quiz_id))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Error adding question: {str(e)}')
                flash('An error occurred while adding the question.', 'danger')
        
        return render_template('add_question.html', form=form, quiz=quiz)
    except Exception as e:
        app.logger.error(f'Error in add_question route: {str(e)}')
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('quiz_management'))

@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
@login_required
def edit_question(question_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    question = Question.query.get_or_404(question_id)
    form = QuestionForm(obj=question)
    
    if form.validate_on_submit():
        try:
            # Get the actual option value based on the selected option
            selected_option = form.correct_option.data
            correct_answer = getattr(form, selected_option).data
            
            question.question_statement = form.question_statement.data
            question.option1 = form.option1.data
            question.option2 = form.option2.data
            question.option3 = form.option3.data
            question.option4 = form.option4.data
            question.correct_option = correct_answer  # Store the actual answer text
            
            db.session.commit()
            # Invalidate cache after successful question update
            invalidate_admin_cache()
            invalidate_global_cache()
            flash('Question updated successfully.', 'success')
            return redirect(url_for('manage_questions', quiz_id=question.quiz_id))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error updating question: {str(e)}')
            flash('An error occurred while updating the question.', 'danger')
    
    return render_template('edit_question.html', form=form, question=question)

@app.route('/delete_question/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    question = Question.query.get_or_404(question_id)
    quiz_id = question.quiz_id
    try:
        db.session.delete(question)
        db.session.commit()
        # Invalidate cache after successful question deletion
        invalidate_admin_cache()
        invalidate_global_cache()
        flash('Question deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting question: {str(e)}')
        flash('An error occurred while deleting the question.', 'danger')
    
    return redirect(url_for('manage_questions', quiz_id=quiz_id))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Add debugging information
        app.logger.info(f'Loading user dashboard for user: {current_user.id}')
        
        # Get all attempts by the user with eager loading
        attempts = QuizAttempt.query.options(
            joinedload(QuizAttempt.quiz).joinedload(Quiz.chapter).joinedload(Chapter.subject)
        ).filter_by(user_id=current_user.id).all()
        
        app.logger.info(f'Found {len(attempts)} attempts for user')
        
        # Get unique attempted quiz IDs
        attempted_quiz_ids = set(attempt.quiz_id for attempt in attempts)
        
        # Get all available quizzes with their attempt status
        available_quizzes = []
        quizzes = Quiz.query.options(
            joinedload(Quiz.chapter).joinedload(Chapter.subject)
        ).join(Chapter).join(Subject).all()
        
        app.logger.info(f'Found {len(quizzes)} total quizzes')
        
        for quiz in quizzes:
            try:
                available_quizzes.append({
                    'id': quiz.id,
                    'name': quiz.remarks,
                    'subject': quiz.chapter.subject.name,
                    'chapter': quiz.chapter.name,
                    'duration': quiz.time_duration,
                    'is_attempted': quiz.id in attempted_quiz_ids,
                    'url': url_for('attempt_quiz', quiz_id=quiz.id)
                })
            except Exception as quiz_error:
                app.logger.error(f'Error processing quiz {quiz.id}: {str(quiz_error)}')
                # Skip this quiz if there's an error
                continue
        
        app.logger.info(f'Processed {len(available_quizzes)} available quizzes')
        
        # Calculate statistics
        total_attempts = len(attempts)
        total_available = len(available_quizzes)
        
        if attempts:
            total_score = sum(attempt.score for attempt in attempts)
            total_questions = sum(attempt.total_questions for attempt in attempts)
            average_score = (total_score / total_questions) * 100 if total_questions > 0 else 0
            best_score = max((attempt.score / attempt.total_questions * 100) for attempt in attempts) if attempts else 0
        else:
            average_score = 0
            best_score = 0
        
        # Get unique subjects
        subjects = list(set(quiz['subject'] for quiz in available_quizzes))
        
        # Calculate subject-wise scores for chart
        subject_scores = {}
        for attempt in attempts:
            subject_name = attempt.quiz.chapter.subject.name
            if subject_name not in subject_scores:
                subject_scores[subject_name] = []
            score_percentage = (attempt.score / attempt.total_questions * 100) if attempt.total_questions > 0 else 0
            subject_scores[subject_name].append(score_percentage)
        
        # Calculate average score per subject
        for subject in subject_scores:
            subject_scores[subject] = sum(subject_scores[subject]) / len(subject_scores[subject])
        
        # Get recent attempts for chart (last 5)
        recent_attempts = []
        for attempt in sorted(attempts, key=lambda x: x.attempt_date, reverse=True)[:5]:
            recent_attempts.append({
                'quiz_name': attempt.quiz.remarks,
                'score_percentage': (attempt.score / attempt.total_questions * 100) if attempt.total_questions > 0 else 0
            })
        
        # Invalidate cache if user has new attempts
        if total_attempts > 0:
            invalidate_user_cache(current_user.id)
        
        # Always invalidate user cache to ensure fresh data
        invalidate_user_cache(current_user.id)
        
        response = make_response(render_template('user_dashboard.html',
                             available_quizzes=available_quizzes,
                             attempted_quizzes=available_quizzes[:total_attempts],  # Just for count
                             average_score=average_score,
                             best_score=best_score,
                             subjects=subjects,
                             subject_scores=subject_scores,
                             recent_attempts=recent_attempts))
        
        # Add cache headers to prevent browser caching
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        app.logger.error(f'User dashboard error: {str(e)}')
        flash('An error occurred while loading the dashboard.', 'danger')
        return redirect(url_for('index'))

@app.route('/debug/quizzes')
@login_required
def debug_quizzes():
    """Debug route to check quiz data"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Check all quizzes
        quizzes = Quiz.query.all()
        quiz_data = []
        
        for quiz in quizzes:
            try:
                quiz_data.append({
                    'id': quiz.id,
                    'name': quiz.remarks,
                    'chapter_id': quiz.chapter_id,
                    'chapter_name': quiz.chapter.name if quiz.chapter else 'No Chapter',
                    'subject_name': quiz.chapter.subject.name if quiz.chapter and quiz.chapter.subject else 'No Subject',
                    'duration': quiz.time_duration,
                    'questions_count': len(quiz.questions)
                })
            except Exception as e:
                quiz_data.append({
                    'id': quiz.id,
                    'error': str(e)
                })
        
        return jsonify({
            'total_quizzes': len(quizzes),
            'quizzes': quiz_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/attempt_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def attempt_quiz(quiz_id):
    if current_user.is_admin:
        flash('Admins cannot attempt quizzes.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        quiz = Quiz.query.get_or_404(quiz_id)
        
        if request.method == 'POST':
            try:
                # Initialize variables
                score = 0
                total_questions = len(quiz.questions) if quiz and quiz.questions else 0
                
                app.logger.info(f'Processing quiz submission for quiz {quiz_id} with {total_questions} questions')
                
                # Process each question
                for question in quiz.questions:
                    try:
                        question_id = question.id
                        selected_option = request.form.get(f'question_{question_id}')
                        
                        app.logger.info(f'Question {question_id}: selected_option={selected_option}, correct_option={question.correct_option}')
                        
                        if selected_option and selected_option in ['option1', 'option2', 'option3', 'option4']:
                            # Get the actual answer text based on the selected option
                            selected_answer = getattr(question, selected_option, None)
                            app.logger.info(f'Question {question_id}: selected_answer={selected_answer}')
                            
                            # Check if answer is correct
                            if selected_answer and selected_answer == question.correct_option:
                                score += 1
                                app.logger.info(f'Question {question_id}: Correct! Score now: {score}')
                            else:
                                app.logger.info(f'Question {question_id}: Incorrect. Expected: {question.correct_option}, Got: {selected_answer}')
                        else:
                            app.logger.info(f'Question {question_id}: No valid option selected')
                    except Exception as question_error:
                        app.logger.error(f'Error processing question {question.id}: {str(question_error)}')
                        continue
                
                app.logger.info(f'Final score: {score}/{total_questions}')
                
                # Create quiz attempt record
                try:
                    quiz_attempt = QuizAttempt(
                        user_id=current_user.id,
                        quiz_id=quiz_id,
                        score=score,
                        total_questions=total_questions,
                        attempt_date=datetime.now()
                    )
                    db.session.add(quiz_attempt)
                    db.session.commit()
                    app.logger.info(f'Quiz attempt saved successfully for user {current_user.id}')
                except Exception as db_error:
                    db.session.rollback()
                    app.logger.error(f'Database error saving quiz attempt: {str(db_error)}')
                    flash('An error occurred while saving your quiz results. Please try again.', 'danger')
                    return redirect(url_for('user_dashboard'))
                
                # Invalidate user cache after quiz attempt
                try:
                    invalidate_user_cache(current_user.id)
                except Exception as cache_error:
                    app.logger.warning(f'Cache invalidation failed: {str(cache_error)}')
                
                # Calculate percentage and show success message
                percentage = (score / total_questions * 100) if total_questions > 0 else 0
                flash(f'Quiz submitted successfully! Your score: {score}/{total_questions} ({percentage:.1f}%)', 'success')
                return redirect(url_for('user_dashboard'))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Error submitting quiz: {str(e)}')
                app.logger.error(f'Quiz ID: {quiz_id}, User ID: {current_user.id}')
                app.logger.error(f'Form data: {dict(request.form)}')
                app.logger.error(f'Quiz questions count: {len(quiz.questions) if quiz else "No quiz"}')
                
                # Log more details about the quiz and questions
                if quiz and quiz.questions:
                    for i, question in enumerate(quiz.questions):
                        try:
                            app.logger.error(f'Question {i+1}: ID={question.id}, Statement="{question.question_statement[:50]}..."')
                            app.logger.error(f'  Options: {question.option1}, {question.option2}, {question.option3}, {question.option4}')
                            app.logger.error(f'  Correct: {question.correct_option}')
                        except Exception as log_error:
                            app.logger.error(f'Error logging question details: {str(log_error)}')
                
                flash('An error occurred while submitting your quiz. Please try again.', 'danger')
                return redirect(url_for('user_dashboard'))
        
        return render_template('attempt_quiz.html', quiz=quiz)
        
    except Exception as e:
        app.logger.error(f'Error in attempt_quiz route: {str(e)}')
        flash('An error occurred while loading the quiz. Please try again.', 'danger')
        return redirect(url_for('user_dashboard'))

@app.route('/user/scores')
@login_required
def user_scores():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    attempts = QuizAttempt.query.filter_by(user_id=current_user.id).all()
    return render_template('user_scores.html', attempts=attempts)

@app.route('/user/summary')
@login_required
def user_summary():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    # Get all attempts by the user with eager loading to avoid N+1 queries
    attempts = QuizAttempt.query.options(
        joinedload(QuizAttempt.quiz).joinedload(Quiz.chapter).joinedload(Chapter.subject)
    ).filter_by(user_id=current_user.id).all()
    
    # Get unique attempted quiz IDs
    attempted_quiz_ids = set(attempt.quiz_id for attempt in attempts)
    total_unique_quizzes = len(attempted_quiz_ids)
    
    # Calculate overall statistics
    if attempts:
        total_score = sum(attempt.score for attempt in attempts)
        total_questions = sum(attempt.total_questions for attempt in attempts)
        average_score = (total_score / total_questions) * 100 if total_questions > 0 else 0
        best_score = max((attempt.score / attempt.total_questions * 100) for attempt in attempts) if attempts else 0
    else:
        average_score = 0
        best_score = 0
    
    # Get all available quizzes with their attempt status using eager loading
    available_quizzes = []
    quizzes = Quiz.query.options(
        joinedload(Quiz.chapter).joinedload(Chapter.subject)
    ).join(Chapter).join(Subject).all()
    
    for quiz in quizzes:
        available_quizzes.append({
            'name': quiz.remarks,
            'chapter': quiz.chapter.name,
            'subject': quiz.chapter.subject.name,
            'is_attempted': quiz.id in attempted_quiz_ids
        })
    
    total_available_quizzes = len(quizzes)
    
    # Get subject-wise statistics (now using pre-loaded data)
    subject_stats = {}
    subject_labels = []
    subject_scores = []
    
    for attempt in attempts:
        # No need for additional queries - data is already loaded
        subject_name = attempt.quiz.chapter.subject.name
        if subject_name not in subject_stats:
            subject_stats[subject_name] = {
                'attempts': 0,
                'total_score': 0,
                'total_questions': 0
            }
        stats = subject_stats[subject_name]
        stats['attempts'] += 1
        stats['total_score'] += attempt.score
        stats['total_questions'] += attempt.total_questions
    
    # Calculate percentages and prepare chart data
    for subject_name, stats in subject_stats.items():
        percentage = (stats['total_score'] / stats['total_questions']) * 100 if stats['total_questions'] > 0 else 0
        subject_labels.append(subject_name)
        subject_scores.append(round(percentage, 2))
    
    # Get month-wise attempt statistics
    month_stats = {}
    for attempt in attempts:
        month_key = attempt.attempt_date.strftime('%Y-%m')
        if month_key not in month_stats:
            month_stats[month_key] = {
                'month_name': attempt.attempt_date.strftime('%B %Y'),
                'attempts': 0,
                'total_score': 0,
                'total_questions': 0,
                'quizzes': set()
            }
        stats = month_stats[month_key]
        stats['attempts'] += 1
        stats['total_score'] += attempt.score
        stats['total_questions'] += attempt.total_questions
        stats['quizzes'].add(attempt.quiz_id)
    
    # Convert month stats to list and calculate percentages
    month_wise_stats = []
    for month_key in sorted(month_stats.keys(), reverse=True):
        stats = month_stats[month_key]
        percentage = (stats['total_score'] / stats['total_questions'] * 100) if stats['total_questions'] > 0 else 0
        month_wise_stats.append({
            'month': stats['month_name'],
            'attempts': stats['attempts'],
            'unique_quizzes': len(stats['quizzes']),
            'score': round(percentage, 1)
        })
    
    return render_template('user_summary.html',
                         total_quizzes=total_unique_quizzes,
                         average_score=average_score,
                         best_score=best_score,
                         total_available_quizzes=total_available_quizzes,
                         subject_labels=subject_labels,
                         subject_scores=subject_scores,
                         month_wise_stats=month_wise_stats,
                         attempts=attempts)

@app.route('/user/summary/download')
@login_required
def download_summary():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    # Create a BytesIO buffer to receive PDF data
    buffer = BytesIO()
    
    # Create the PDF object using ReportLab
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Add title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    )
    elements.append(Paragraph("Quiz Performance Summary", title_style))
    elements.append(Spacer(1, 20))
    
    # Get user's quiz attempts
    attempts = QuizAttempt.query.filter_by(user_id=current_user.id).all()
    
    # Calculate overall statistics
    total_unique_quizzes = len(set(attempt.quiz_id for attempt in attempts))
    if attempts:
        total_score = sum(attempt.score for attempt in attempts)
        total_questions = sum(attempt.total_questions for attempt in attempts)
        average_score = (total_score / total_questions * 100) if total_questions > 0 else 0
    else:
        average_score = 0
    
    # Add overall statistics
    elements.append(Paragraph("Overall Statistics", styles['Heading2']))
    overall_data = [
        ["Total Quizzes Attempted", str(total_unique_quizzes)],
        ["Average Score", f"{average_score:.1f}%"]
    ]
    overall_table = Table(overall_data)
    overall_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 14),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(overall_table)
    elements.append(Spacer(1, 20))
    
    # Add month-wise statistics
    elements.append(Paragraph("Month-wise Statistics", styles['Heading2']))
    
    month_stats = {}
    for attempt in attempts:
        month_key = attempt.attempt_date.strftime('%Y-%m')
        if month_key not in month_stats:
            month_stats[month_key] = {
                'month_name': attempt.attempt_date.strftime('%B %Y'),
                'attempts': 0,
                'total_score': 0,
                'total_questions': 0,
                'quizzes': set()
            }
        stats = month_stats[month_key]
        stats['attempts'] += 1
        stats['total_score'] += attempt.score
        stats['total_questions'] += attempt.total_questions
        stats['quizzes'].add(attempt.quiz_id)
    
    # Create month-wise table data
    month_data = [["Month", "Total Attempts", "Unique Quizzes", "Average Score"]]
    for month_key in sorted(month_stats.keys(), reverse=True):
        stats = month_stats[month_key]
        percentage = (stats['total_score'] / stats['total_questions'] * 100) if stats['total_questions'] > 0 else 0
        month_data.append([
            stats['month_name'],
            str(stats['attempts']),
            str(len(stats['quizzes'])),
            f"{percentage:.1f}%"
        ])
    
    month_table = Table(month_data)
    month_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ALIGN', (1, 1), (-1, -1), 'CENTER')
    ]))
    elements.append(month_table)
    
    # Build the PDF document
    doc.build(elements)
    
    # Move to the beginning of the buffer
    buffer.seek(0)
    
    # Return the PDF file
    return send_file(
        buffer,
        download_name=f'quiz_summary_{datetime.now().strftime("%Y%m%d")}.pdf',
        as_attachment=True,
        mimetype='application/pdf'
    )

@app.route('/admin_summary')
@login_required
def admin_summary():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Get all subjects and users
    subjects = Subject.query.all()
    users = User.query.filter_by(is_admin=False).all()
    
    # Calculate summary statistics
    total_subjects = len(subjects)
    total_chapters = sum(len(subject.chapters) for subject in subjects)
    total_quizzes = sum(len(chapter.quizzes) for subject in subjects for chapter in subject.chapters)
    total_questions = sum(len(quiz.questions) for subject in subjects for chapter in subject.chapters for quiz in chapter.quizzes)
    total_users = len(users)
    
    # Get top scores for each quiz
    top_scores = []
    quizzes = Quiz.query.all()
    for quiz in quizzes:
        # Get all attempts for this quiz
        attempts = QuizAttempt.query.filter_by(quiz_id=quiz.id).all()
        # Count unique users who attempted this quiz
        unique_users = len(set(attempt.user_id for attempt in attempts))
        
        # Get the highest score for this quiz
        best_attempt = QuizAttempt.query.filter_by(quiz_id=quiz.id)\
            .order_by((QuizAttempt.score * 100.0 / QuizAttempt.total_questions).desc())\
            .first()
        
        if best_attempt:
            # Get the user who achieved this score
            user = User.query.get(best_attempt.user_id)
            percentage = (best_attempt.score / best_attempt.total_questions * 100)
            
            top_scores.append({
                'quiz_name': quiz.remarks,
                'chapter': quiz.chapter.name,
                'subject': quiz.chapter.subject.name,
                'user': user.full_name,
                'score': best_attempt.score,
                'total': best_attempt.total_questions,
                'percentage': round(percentage, 1),
                'date': best_attempt.attempt_date.strftime('%Y-%m-%d'),
                'attempts': unique_users
            })
    
    # Sort top scores by percentage in descending order
    top_scores.sort(key=lambda x: x['percentage'], reverse=True)
    
    # Get subject-wise quiz attempts
    subject_attempts = []
    for subject in subjects:
        # Count attempts for all quizzes in this subject
        attempt_count = db.session.query(db.func.count(QuizAttempt.id))\
            .join(Quiz, QuizAttempt.quiz_id == Quiz.id)\
            .join(Chapter, Quiz.chapter_id == Chapter.id)\
            .filter(Chapter.subject_id == subject.id)\
            .scalar()
        
        if attempt_count > 0:
            subject_attempts.append({
                'subject_name': subject.name,
                'total_attempts': attempt_count
            })
    
    # Sort subject attempts by number of attempts in descending order
    subject_attempts.sort(key=lambda x: x['total_attempts'], reverse=True)
    
    summary = {
        'total_subjects': total_subjects,
        'total_chapters': total_chapters,
        'total_quizzes': total_quizzes,
        'total_questions': total_questions,
        'total_users': total_users
    }
    
    return render_template('admin_summary.html', 
                         subjects=subjects,
                         users=users,
                         summary=summary,
                         top_scores=top_scores,
                         subject_attempts=subject_attempts)

@app.route('/admin/reminder_settings', methods=['GET', 'POST'])
@login_required
def reminder_settings():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    from forms import ReminderSettingsForm
    from models import ReminderSettings
    
    # Get or create reminder settings
    settings = ReminderSettings.query.first()
    if not settings:
        settings = ReminderSettings()
        db.session.add(settings)
        db.session.commit()
    
    form = ReminderSettingsForm()
    
    if request.method == 'GET':
        # Pre-populate form with current settings
        form.daily_reminder_hour.data = settings.daily_reminder_hour
        form.daily_reminder_minute.data = settings.daily_reminder_minute
        form.monthly_reminder_day.data = settings.monthly_reminder_day
        form.monthly_reminder_hour.data = settings.monthly_reminder_hour
        form.monthly_reminder_minute.data = settings.monthly_reminder_minute
        form.daily_reminders_enabled.data = settings.daily_reminders_enabled
        form.monthly_reminders_enabled.data = settings.monthly_reminders_enabled
    
    if form.validate_on_submit():
        try:
            # Update settings
            settings.daily_reminder_hour = form.daily_reminder_hour.data
            settings.daily_reminder_minute = form.daily_reminder_minute.data
            settings.monthly_reminder_day = form.monthly_reminder_day.data
            settings.monthly_reminder_hour = form.monthly_reminder_hour.data
            settings.monthly_reminder_minute = form.monthly_reminder_minute.data
            settings.daily_reminders_enabled = form.daily_reminders_enabled.data
            settings.monthly_reminders_enabled = form.monthly_reminders_enabled.data
            
            db.session.commit()
            
            # Invalidate cache to reflect changes
            invalidate_admin_cache()
            
            # Update Celery scheduled tasks
            try:
                from celery_config import update_scheduled_tasks
                from celery_config import celery
                update_scheduled_tasks(celery)
                app.logger.info('Celery scheduled tasks updated successfully')
            except Exception as e:
                app.logger.warning(f'Failed to update Celery scheduled tasks: {str(e)}')
            
            flash('Reminder settings updated successfully!', 'success')
            return redirect(url_for('reminder_settings'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error updating reminder settings: {str(e)}')
            flash('An error occurred while updating reminder settings.', 'danger')
    
    return render_template('reminder_settings.html', form=form, settings=settings)

@app.route('/add_subject', methods=['GET', 'POST'])
@login_required
def add_subject():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    form = SubjectForm()
    if form.validate_on_submit():
        subject = Subject(
            name=form.name.data,
            description=form.description.data
        )
        db.session.add(subject)
        try:
            db.session.commit()
            # Invalidate cache after successful subject creation
            invalidate_admin_cache()
            invalidate_global_cache()
            flash('Subject added successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error adding subject: {str(e)}')
            flash('An error occurred while adding the subject.', 'danger')
    
    return render_template('add_subject.html', form=form)

@app.route('/edit_subject/<int:subject_id>', methods=['GET', 'POST'])
@login_required
def edit_subject(subject_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    subject = Subject.query.get_or_404(subject_id)
    form = SubjectForm(obj=subject)
    
    if form.validate_on_submit():
        subject.name = form.name.data
        subject.description = form.description.data
        try:
            db.session.commit()
            # Invalidate cache after successful subject update
            invalidate_admin_cache()
            invalidate_global_cache()
            flash('Subject updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error updating subject: {str(e)}')
            flash('An error occurred while updating the subject.', 'danger')
    
    return render_template('edit_subject.html', form=form, subject=subject)

@app.route('/delete_subject/<int:subject_id>', methods=['POST'])
@login_required
def delete_subject(subject_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    subject = Subject.query.get_or_404(subject_id)
    try:
        # Delete all chapters and their associated quizzes and attempts
        for chapter in subject.chapters:
            for quiz in chapter.quizzes:
                Question.query.filter_by(quiz_id=quiz.id).delete()
                QuizAttempt.query.filter_by(quiz_id=quiz.id).delete()
                db.session.delete(quiz)
            db.session.delete(chapter)
        db.session.delete(subject)
        db.session.commit()
        # Invalidate cache after successful deletion
        invalidate_admin_cache()
        invalidate_global_cache()
        flash('Subject deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting subject: {str(e)}')
        flash('An error occurred while deleting the subject.', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/add_chapter/<int:subject_id>', methods=['GET', 'POST'])
@login_required
def add_chapter(subject_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    subject = Subject.query.get_or_404(subject_id)
    form = ChapterForm()
    
    if form.validate_on_submit():
        chapter = Chapter(
            name=form.name.data,
            description=form.description.data,
            subject_id=subject_id
        )
        db.session.add(chapter)
        try:
            db.session.commit()
            # Invalidate cache after successful chapter creation
            invalidate_admin_cache()
            invalidate_global_cache()
            flash('Chapter added successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error adding chapter: {str(e)}')
            flash('An error occurred while adding the chapter.', 'danger')
    
    return render_template('add_chapter.html', form=form, subject=subject)

@app.route('/edit_chapter/<int:chapter_id>', methods=['GET', 'POST'])
@login_required
def edit_chapter(chapter_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    chapter = Chapter.query.get_or_404(chapter_id)
    form = ChapterForm(obj=chapter)
    
    if form.validate_on_submit():
        chapter.name = form.name.data
        chapter.description = form.description.data
        try:
            db.session.commit()
            # Invalidate cache after successful chapter update
            invalidate_admin_cache()
            invalidate_global_cache()
            flash('Chapter updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error updating chapter: {str(e)}')
            flash('An error occurred while updating the chapter.', 'danger')
    
    return render_template('edit_chapter.html', form=form, chapter=chapter)

@app.route('/delete_chapter/<int:chapter_id>', methods=['POST'])
@login_required
def delete_chapter(chapter_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    chapter = Chapter.query.get_or_404(chapter_id)
    try:
        # Delete all quizzes and their associated questions and attempts
        for quiz in chapter.quizzes:
            Question.query.filter_by(quiz_id=quiz.id).delete()
            QuizAttempt.query.filter_by(quiz_id=quiz.id).delete()
            db.session.delete(quiz)
        db.session.delete(chapter)
        db.session.commit()
        # Invalidate cache after successful deletion
        invalidate_admin_cache()
        invalidate_global_cache()
        flash('Chapter deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting chapter: {str(e)}')
        flash('An error occurred while deleting the chapter.', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if current_user.is_admin:
        flash('Admin profile cannot be modified.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    form = UserProfileForm(obj=current_user)
    
    # Pre-populate form with current user data
    if request.method == 'GET':
        form.email.data = current_user.username
        form.full_name.data = current_user.full_name
        form.qualification.data = current_user.qualification
        form.date_of_birth.data = current_user.dob
    
    if form.validate_on_submit():
        try:
            # Update basic information
            current_user.username = form.email.data
            current_user.full_name = form.full_name.data
            current_user.qualification = form.qualification.data
            current_user.dob = form.date_of_birth.data
            
            # Handle password change if requested
            if form.new_password.data:
                # Verify current password
                if not check_password_hash(current_user.password, form.current_password.data):
                    flash('Current password is incorrect.', 'danger')
                    return render_template('profile.html', form=form, today_date=date.today().isoformat())
                
                # Update password
                current_user.password = generate_password_hash(form.new_password.data)
                flash('Password updated successfully.', 'success')
            elif form.current_password.data:
                # Verify current password for non-password changes
                if not check_password_hash(current_user.password, form.current_password.data):
                    flash('Current password is incorrect.', 'danger')
                    return render_template('profile.html', form=form, today_date=date.today().isoformat())
            
            db.session.commit()
            # Invalidate user cache after profile update
            invalidate_user_cache(current_user.id)
            flash('Profile updated successfully.', 'success')
            return redirect(url_for('profile'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Profile update error: {str(e)}')
            flash('An error occurred while updating your profile.', 'danger')
    
    return render_template('profile.html', form=form, today_date=date.today().isoformat())

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot edit admin user.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    form = UserProfileForm(obj=user)
    
    # Pre-populate form with user data
    if request.method == 'GET':
        form.email.data = user.username
        form.full_name.data = user.full_name
        form.qualification.data = user.qualification
        form.date_of_birth.data = user.dob
    
    if form.validate_on_submit():
        try:
            user.username = form.email.data
            user.full_name = form.full_name.data
            user.qualification = form.qualification.data
            user.dob = form.date_of_birth.data
            
            if form.new_password.data:
                user.password = generate_password_hash(form.new_password.data)
            
            db.session.commit()
            # Invalidate user cache after user update
            invalidate_user_cache(user.id)
            flash('User updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'User update error: {str(e)}')
            flash('An error occurred while updating the user.', 'danger')
    
    return render_template('edit_user.html', form=form, user=user, today_date=date.today().isoformat())

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot delete admin user.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Delete all quiz attempts associated with this user
        QuizAttempt.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'User deletion error: {str(e)}')
        flash('An error occurred while deleting the user.', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/user/quiz_attempts/export', methods=['POST'])
@login_required
def export_user_quiz_attempts():
    if current_user.is_admin:
        flash('Admins cannot export quiz attempts.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Check if Celery is available (Redis running)
        try:
            # Try to trigger Celery task
            app.logger.info(f'Attempting to trigger Celery task for user {current_user.id}')
            task = export_user_quiz_data_csv.delay(current_user.id)
            app.logger.info(f'Celery task triggered successfully: {task.id}')
            flash('Your quiz data export has been started. You will receive an email when it\'s ready.', 'info')
        except Exception as celery_error:
            app.logger.warning(f'Celery not available, using direct export: {str(celery_error)}')
            # Fallback: Direct CSV generation and download
            from io import StringIO
            import csv
            
            # Get user's quiz attempts
            attempts = QuizAttempt.query.filter_by(user_id=current_user.id).all()
            
            if not attempts:
                flash('No quiz attempts found to export.', 'warning')
                return redirect(url_for('user_dashboard'))
            
            # Create CSV content
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(['Quiz ID', 'Subject', 'Chapter', 'Quiz Date', 'Attempt Date', 'Score (%)', 'Total Questions', 'Remarks'])
            
            for attempt in attempts:
                quiz = attempt.quiz
                if quiz and quiz.chapter and quiz.chapter.subject:
                    writer.writerow([
                        quiz.id,
                        quiz.chapter.subject.name,
                        quiz.chapter.name,
                        quiz.created_date.strftime('%Y-%m-%d') if quiz.created_date else 'N/A',
                        attempt.attempt_date.strftime('%Y-%m-%d %H:%M') if attempt.attempt_date else 'N/A',
                        f"{(attempt.score / attempt.total_questions * 100):.1f}" if attempt.total_questions > 0 else '0.0',
                        attempt.total_questions,
                        'Completed' if attempt.score > 0 else 'No score'
                    ])
            
            # Create response
            from flask import Response
            output.seek(0)
            response = Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename=quiz_data_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
            )
            return response
        
        return redirect(url_for('user_dashboard'))
    except Exception as e:
        app.logger.error(f'Error exporting quiz attempts: {str(e)}')
        flash('An error occurred while exporting quiz attempts.', 'danger')
        return redirect(url_for('user_dashboard'))

@app.route('/task_status/<task_id>')
@login_required
def task_status(task_id):
    task = celery.AsyncResult(task_id)
    if task.state == 'PENDING':
        response = {
            'state': task.state,
            'status': 'Pending...'
        }
    elif task.state != 'FAILURE':
        response = {
            'state': task.state,
            'result': task.result
        }
    else:
        # something went wrong in the background job
        response = {
            'state': task.state,
            'status': str(task.info) # this is the exception raised
        }
    return jsonify(response)

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

@app.errorhandler(404)
def not_found_error(error):
    # Don't log Chrome devtools requests
    if not request.url.endswith('.well-known/appspecific/com.chrome.devtools.json'):
        app.logger.info(f'Page not found: {request.url}')
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    if app.config.get('SHOW_ERROR_DETAILS', False):
        # If SHOW_ERROR_DETAILS is True, raise the error to see the details
        raise error
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def unhandled_exception(error):
    app.logger.error(f'Unhandled Exception: {error}')
    if app.config.get('SHOW_ERROR_DETAILS', False):
        return f'<h1>Internal Server Error</h1><p>{str(error)}</p>', 500
    return render_template('500.html'), 500

@app.route('/start_quiz/<int:quiz_id>')
@login_required
def start_quiz(quiz_id):
    """Start a quiz - redirect to attempt_quiz route"""
    try:
        quiz = Quiz.query.get_or_404(quiz_id)
        
        # Check if user has already attempted this quiz
        existing_attempt = QuizAttempt.query.filter_by(
            user_id=current_user.id,
            quiz_id=quiz_id
        ).first()
        
        if existing_attempt:
            flash('You have already attempted this quiz.', 'warning')
            return redirect(url_for('user_dashboard'))
        
        # Redirect to attempt_quiz route
        return redirect(url_for('attempt_quiz', quiz_id=quiz_id))
        
    except Exception as e:
        app.logger.error(f'Error starting quiz {quiz_id}: {str(e)}')
        flash('Error starting quiz. Please try again.', 'danger')
        return redirect(url_for('user_dashboard'))



@app.route('/user_profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    """User profile management route - separate from admin profile"""
    if current_user.is_admin:
        flash('Admin profile cannot be modified.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    form = UserProfileForm()
    
    # Pre-populate form with current user data
    if request.method == 'GET':
        form.email.data = current_user.username
        form.full_name.data = current_user.full_name
        form.qualification.data = current_user.qualification
        form.date_of_birth.data = current_user.dob
    
    if form.validate_on_submit():
        try:
            # Update user profile
            current_user.username = form.email.data
            current_user.full_name = form.full_name.data
            current_user.qualification = form.qualification.data
            current_user.dob = form.date_of_birth.data
            
            # Handle password change if provided
            if form.new_password.data:
                if not check_password_hash(current_user.password, form.current_password.data):
                    flash('Current password is incorrect.', 'danger')
                    return render_template('user_profile.html', form=form)
                
                current_user.password = generate_password_hash(form.new_password.data)
                flash('Password updated successfully.', 'success')
            elif form.current_password.data:
                # Verify current password for non-password changes
                if not check_password_hash(current_user.password, form.current_password.data):
                    flash('Current password is incorrect.', 'danger')
                    return render_template('user_profile.html', form=form)
            
            db.session.commit()
            # Invalidate user cache after profile update
            invalidate_user_cache(current_user.id)
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('user_profile'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error in user_profile: {str(e)}')
            flash('Error updating profile. Please try again.', 'danger')
    
    return render_template('user_profile.html', form=form)

@app.route('/api/search')
@login_required
def search_api():
    """Search API endpoint for admin dashboard"""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    query = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'all')
    
    if not query or len(query) < 2:
        return jsonify({'results': []})
    
    results = []
    
    try:
        # Search users
        if search_type in ['all', 'users']:
            users = User.query.filter(
                or_(
                    User.username.ilike(f'%{query}%'),
                    User.full_name.ilike(f'%{query}%'),
                    User.qualification.ilike(f'%{query}%')
                )
            ).limit(10).all()
            
            for user in users:
                results.append({
                    'id': user.id,
                    'type': 'user',
                    'name': user.full_name,
                    'email': user.username,
                    'qualification': user.qualification,
                    'url': url_for('edit_user', user_id=user.id)
                })
        
        # Search subjects
        if search_type in ['all', 'subjects']:
            subjects = Subject.query.filter(
                or_(
                    Subject.name.ilike(f'%{query}%'),
                    Subject.description.ilike(f'%{query}%')
                )
            ).limit(10).all()
            
            for subject in subjects:
                results.append({
                    'id': subject.id,
                    'type': 'subject',
                    'name': subject.name,
                    'description': subject.description,
                    'url': url_for('edit_subject', subject_id=subject.id)
                })
        
        # Search chapters
        if search_type in ['all', 'chapters']:
            chapters = Chapter.query.join(Subject).filter(
                or_(
                    Chapter.name.ilike(f'%{query}%'),
                    Chapter.description.ilike(f'%{query}%'),
                    Subject.name.ilike(f'%{query}%')
                )
            ).limit(10).all()
            
            for chapter in chapters:
                results.append({
                    'id': chapter.id,
                    'type': 'chapter',
                    'name': chapter.name,
                    'description': chapter.description,
                    'subject': chapter.subject.name,
                    'url': url_for('edit_chapter', chapter_id=chapter.id)
                })
        
        # Search quizzes
        if search_type in ['all', 'quizzes']:
            quizzes = Quiz.query.join(Chapter).join(Subject).filter(
                or_(
                    Quiz.remarks.ilike(f'%{query}%'),
                    Chapter.name.ilike(f'%{query}%'),
                    Subject.name.ilike(f'%{query}%')
                )
            ).limit(10).all()
            
            for quiz in quizzes:
                results.append({
                    'id': quiz.id,
                    'type': 'quiz',
                    'name': quiz.remarks,
                    'chapter': quiz.chapter.name,
                    'subject': quiz.chapter.subject.name,
                    'duration': quiz.time_duration,
                    'url': url_for('edit_quiz', quiz_id=quiz.id)
                })
        
        return jsonify({'results': results})
        
    except Exception as e:
        app.logger.error(f'Search error: {str(e)}')
        return jsonify({'error': 'Search failed'}), 500

if __name__ == '__main__':
    # Create argument parser
    parser = argparse.ArgumentParser(description='Run the Quiz Master application')
    parser.add_argument('--debug-errors', 
                       action='store_true',
                       help='Show detailed error messages instead of 500.html')
    
    args = parser.parse_args()
    
    # Set the configuration based on command line argument
    app.config['SHOW_ERROR_DETAILS'] = args.debug_errors
    
    # Create the database tables
    with app.app_context():
        db.create_all()
    
    app.run(debug=True, host='0.0.0.0', port=5000)