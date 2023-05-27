import os
from functools import wraps
import clamd  

from flask import current_app as app
from flask import abort, Blueprint, render_template, redirect, url_for, flash
from flask import Markup
from flask_limiter.util import get_remote_address
from flask_login import login_user, logout_user, current_user, login_required
from flask_mail import Message
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.utils import secure_filename

from app import db, limiter, logger, mail, login_manager
from app.forms import RegisterForm, LoginForm, FeedbackForm
from app.models import User, Feedback

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


# Initialize ClamAV scanner
clamd_socket = '/var/run/clamav/clamd.ctl'  # Adjust the socket path based on your ClamAV configuration
clamav = clamd.ClamdUnixSocket(clamd_socket)

# Scan file for viruses using ClamAV
def scan_file(file):
    try:
        response = clamav.scan_stream(file.stream)
        return response['stream'] == 'OK'
    except Exception as e:
        logger.error('Error scanning file: {}'.format(str(e)))
        return False

# Create an instance of URLSafeTimedSerializer

# Rate Limiter
# limiter.init_app(app)

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('You are not authorized to access this page.', 'danger')
            return redirect(url_for('main.main.index'))
        return f(*args, **kwargs)
    return decorated_function



# Function to generate a verification token
def generate_verification_token(username):
    # Generate the verification token

    with app.app_context():
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

        token = serializer.dumps(username, salt='email-verification', expires_in=3600)  # Token expires after 1 hour (3600 seconds)
        return token

# Function to send a verification email
def send_verification_email(email, verification_link):
    msg = Message('Account Verification', recipients=[email])
    msg.body = f'Please click on the link below to verify your account:\n{verification_link}'
    mail.send(msg)





main = Blueprint('main', __name__,url_prefix='/main')



# Routes

@main.route('/')
def index():
    print("hello there")
    return render_template('index.html')

@main.route('/register', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Limit to 5 requests per minute
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already taken. Please choose a different username.', 'danger')
            logger.danger('Username already taken: {}'.format(username))
            return redirect(url_for('main.register'))

        # Check if email is  already taken
        if User.query.filter_by(email=email).first():
            flash('Email already taken. Please choose a different email.', 'danger')
            logger.danger('Email already taken: {}'.format(email))
            return redirect(url_for('main.register'))


        # Create a new user
        user = User(username=username, email=email, password=password)
        user.save()

        logger.info('User registered: {}'.format(username))

        # Send verification email
        token = generate_verification_token(username)
        verification_link = url_for('main.verify_email', token=token, _external=True)
        send_verification_email(user.email, verification_link)

        flash('Registration successful. Please check your email to verify your account.', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html', form=form)



@main.route('/verify/<token>')
def verify(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    try:
        with app.app_context():
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

            username = serializer.loads(token, salt='email-verification', max_age=3600)  # Token expires after 1 hour (3600 seconds)
            user = User.query.filter_by(username=username).first()
            if user:
                user.email_verified = True
                user.save()
                logger.info('Email verified for user: {}'.format(username))
                flash('Email verification successful. You can now log in.', 'success')
            else:
                flash('Invalid verification token.', 'danger')
    except SignatureExpired:
        flash('Verification token has expired.', 'danger')
    except BadSignature:
        flash('Invalid verification token.', 'danger')

    flash('Account verified successfully. You can now log in.', 'success')
    return redirect(url_for('main.login'))



@main.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Rate limit: 5 requests per minute
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.is_verified and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid username or password. Please try again!', 'warning')
    return render_template('login.html', form=form)



@main.route('/logout')
@login_required
def logout():
    logger.info('User logged out: {}'.format(current_user.username))
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@main.route('/dashboard')
@login_required
def dashboard():
    feedbacks = Feedback.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', feedbacks=feedbacks)

@main.route('/admin')
@login_required
@admin_required
def admin():
    members = User.query.all()
    return render_template('admin.html', members=members)

# Route for enabling/disabling user accounts (admin only)
@main.route('/admin/user/<int:user_id>/toggle_status', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if not current_user.is_admin:
        abort(403)  # Only admin can access this route

    user = User.query.get_or_404(user_id)
    if user == current_user:
        flash('Cannot disable your own account.', 'danger')
    else:
        user.is_active = not user.is_active
        user.save()
        logger.info('User status toggled by admin. User ID: {}, Status: {}'.format(user_id, user.is_active))
        flash('User account status updated.', 'success')

    return redirect(url_for('main.admin_dashboard'))  # Update the route name based on your admin dashboard route


# Route for submitting feedback
@main.route('/feedback', methods=['GET', 'POST'])
@limiter.limit("2/minute")  # Rate limit: maximum 2 requests per minute
@login_required
def feedback():
    if not current_user.is_active or not current_user.email_verified:
        abort(403)  # User is not allowed to submit feedback

    form = FeedbackForm()
    if form.validate_on_submit():
        # Handle file upload
        file = form.file.data
        if file:
            # Validate file type
            if file.content_type != 'application/pdf':
                flash('Only PDF files are allowed.', 'danger')
                return redirect(url_for('main.feedback'))

            # Scan file for viruses
            if scan_file(file):
                flash('File contains viruses or malicious content.', 'danger')
                return redirect(url_for('main.feedback'))

            # Validate file size
            max_file_size = 5 * 1024 * 1024  # 5MB
            if len(file.read()) > max_file_size:
                flash('File size should be less than 5MB.', 'danger')
                return redirect(url_for('main.feedback'))

            # Save the file
            with app.app_context():
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None

        # Create a new Feedback instance
        feedback = Feedback(
            name=form.name.data,
            email=form.email.data,
            comments=form.comments.data,
            file=filename,
            user=current_user
        )
        feedback.save()
        logger.info('New feedback submitted by user: {}'.format(current_user.username))
        flash('Feedback submitted successfully.', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('feedback.html', form=form)



# Route for editing feedback
@main.route('/feedback/edit/<int:feedback_id>', methods=['GET', 'POST'])
@login_required
def edit_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)

    # Check if the feedback belongs to the current user
    if feedback.user != current_user:
        abort(403)  # User is not allowed to edit other users' feedbacks

    form = FeedbackForm(obj=feedback)
    if form.validate_on_submit():
        # Handle file upload
        file = form.file.data
        if file:
            # Validate file type
            if file.content_type != 'application/pdf':
                flash('Only PDF files are allowed.', 'danger')
                return redirect(url_for('main.edit_feedback', feedback_id=feedback_id))

            # Scan file for viruses
            if scan_file(file):
                flash('File contains viruses or malicious content.', 'danger')
                return redirect(url_for('main.edit_feedback', feedback_id=feedback_id))
            
            # Validate file size
            max_file_size = 5 * 1024 * 1024  # 5MB
            if len(file.read()) > max_file_size:
                flash('File size should be less than 5MB.', 'danger')
                return redirect(url_for('main.edit_feedback', feedback_id=feedback_id))


            # Delete the old file, if any
            if feedback.file:
                with app.app_context():
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], feedback.file)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)

                # Save the new file
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = feedback.file

        # Update the feedback
        feedback.name = form.name.data
        feedback.email = form.email.data
        feedback.comments = form.comments.data
        feedback.file = filename
        feedback.save()

        logger.info('Feedback edited by user: {}'.format(current_user.username))
        flash('Feedback updated successfully.', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('edit_feedback.html', form=form, feedback=feedback)


@main.route('/feedback/delete/<int:feedback_id>', methods=['POST'])
@login_required
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)

    # Check if the logged-in user owns the feedback
    if feedback.user_id != current_user.id:
        flash('You are not authorized to delete this feedback.', 'danger')
        return redirect(url_for('main.dashboard'))

    try:
        db.session.delete(feedback)
        db.session.commit()
        flash('Feedback deleted successfully.', 'success')
        logger.info(f'Feedback (ID: {feedback_id}) deleted by user: {current_user.username}')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the feedback. Please try again.', 'danger')
        logger.exception('Error deleting feedback')
    finally:
        db.session.close()

    return redirect(url_for('main.dashboard'))