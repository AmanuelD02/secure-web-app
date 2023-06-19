import copy
from io import BytesIO
import os
from functools import wraps
import random
import secrets
import clamd  
import uuid
import magic


from flask import current_app as app, request, send_from_directory
from flask import abort, Blueprint, render_template, redirect, url_for, flash
from flask import Markup
from flask_limiter.util import get_remote_address
from flask_login import login_user, logout_user, current_user, login_required
from flask_mail import Message
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
import virustotal_python
from werkzeug.utils import secure_filename

from app import db, limiter, logger, mail, login_manager
from app.forms import OTPForm, RegisterForm, LoginForm, FeedbackForm, UserToggleForm
from app.models import Honeypot, User, Feedback




@login_manager.user_loader
def load_user(user_id):
    return User.get_user(user_id)


# Initialize ClamAV scanner
clamd_socket = '/var/run/clamav/clamd.ctl'  # Adjust the socket path based on your ClamAV configuration
clamav = clamd.ClamdUnixSocket()

# Initialize VirusTotal scanner and API key
def scan_file_virustotal(file_data):
    with virustotal_python.Virustotal(os.getenv('VIRUS_TOTAL')) as vtotal:
        # Create dictionary containing the file to send for multipart encoding upload
        files = {"file": ("file.pdf", file_data)}
        resp = vtotal.request("files", files=files, method="POST")
        return resp.json()
# Create an instance of URLSafeTimedSerializer

# Rate Limiter
# limiter.init_app(app)

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('You are not authorized to access this page.', 'danger')
            return render_template('error.html', error_code=500), 500
        return f(*args, **kwargs)
    return decorated_function

def otp_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.otp_verified:
            flash('You are not authorized to access this page.', 'danger')
            return render_template('error.html', error_code=500), 500
        return f(*args, **kwargs)
    return decorated_function

# Function to generate a verification token
def generate_verification_token(username):
    # Generate the verification token

    with app.app_context():
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

        token = serializer.dumps(username, salt='email-verification')  # Token expires after 1 hour (3600 seconds)
        return token

# Function to send a verification email
def send_verification_email(email, verification_link):
    msg = Message('Account Verification', recipients=[email], sender= os.getenv('MAIL_DEFAULT_SENDER'))
    msg.body = f'Please click on the link below to verify your account:\n{verification_link}'
    # txt = f'Please click on the link below to verify your account:\n{verification_link}'
    # mail.send_message(recipients=[email], body=txt, subject='Account Verification',sender= os.getenv('MAIL_USERNAME'))
    mail.send(msg)


def send_OTP(user):
    user.pincode = random.randint(100000, 999999)
    user.save()
    msg = Message('OTP', recipients=[user.email], sender= os.getenv('MAIL_DEFAULT_SENDER'))
    msg.body = f'Your OTP is {user.pincode}'
    mail.send(msg)



main = Blueprint('main', __name__,url_prefix='/')



# Routes

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'GET':
        return render_template('register.html', form=form)

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        name = form.name.data

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already taken. Please choose a different username.', 'danger')
            logger.error('Username already taken: {}'.format(username))
            return redirect(url_for('main.register'))

        # Check if email is  already taken
        if User.query.filter_by(email=email).first():
            flash('Email already taken. Please choose a different email.', 'danger')
            logger.error('Email already taken: {}'.format(email))
            return redirect(url_for('main.register'))

        # Send verification email
        token = generate_verification_token(username)
        verification_link = url_for('main.verify_email', token=token, _external=True)
        send_verification_email(email, verification_link)

        # Create a new user
        user = User(username=username, email=email, name = name)
        user.set_password(password)
        user.save()

        logger.info('User registered: {}'.format(username))


        flash('Registration successful. Please check your email to verify your account.', 'success')
        return redirect(url_for('main.login'))
    else:
        errors = form.errors
        for key, val in errors.items():
            for err in val:
                flash(err, 'danger')
                
        return redirect(url_for('main.register'))
        # flash(form.errors, 'danger')



@main.route('/verify/<token>')
def verify_email(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    try:
        with app.app_context():
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

            username = serializer.loads(token, salt='email-verification', max_age=3600)  # Token expires after 1 hour (3600 seconds)
            user = User.query.filter_by(username=username).first()
            if user:
                user.is_verified = True
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

@login_required
@main.route('/otp', methods=['GET', 'POST'])
def otp():
    if current_user.is_authenticated and current_user.otp_verified:
        return redirect(url_for('main.dashboard'))
    form = OTPForm()
    if request.method == 'GET':
        return render_template('otp.html', form=form)
    if form.validate_on_submit():
        otp = form.otp.data
        user = User.query.filter_by(username=current_user.username).first()
        if user.pincode == otp:
            user.otp_verified = True
            user.save()
            flash('OTP verified successfully. You can now log in.', 'success')
            return redirect(url_for('main.login'))
        
        flash('Incorrect Pin Code', 'danger')

    else:
        errors = form.errors
        for key, val in errors.items():
            for err in val:
                flash(err, 'danger')
    return redirect(url_for('main.otp'))
    


# @limiter.limit("5/minute")  # Rate limit: 5 requests per minute
@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if request.method == 'GET':
        return render_template('login.html', form=form)
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
       

            
        if user and not user.is_verified:
            flash('Please Verify Email', 'warning')

        if user and  user.is_blocked:
            flash('You are Blocked by the admin of this site please contact Admin.', 'warning')
            logger.error('User blocked: {}'.format(username))
    
        elif user and user.check_password(password):
            login_user(user)

            
            flash('OTP sent!', 'success')
            logger.info('User logged in: {}'.format(username))
            send_OTP(user)
            return redirect(url_for('main.otp'))
        else:
            flash('Invalid username or password. Please try again!', 'warning')
            logger.error('Invalid credentials entered for user: {}'.format(username))
            
        return redirect(url_for('main.login'))

    if form.errors:
        for key, val in form.errors.items():
            for err in val:
                flash(err, 'danger')
    
    return redirect(url_for('main.login'))



@main.route('/logout')
@login_required
def logout():
    logger.info('User logged out: {}'.format(current_user.username))
    current_user.otp_verified = False
    current_user.save()
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@main.route('/dashboard')
@login_required
@otp_required
def dashboard():
    
    if current_user.is_admin:
        feedbacks = Feedback.query.all()
    else:
        
        feedbacks = Feedback.query.filter_by(user_id=current_user.id).all()

    form = FeedbackForm() 
    return render_template('dashboard.html', feedbacks=feedbacks, form = form)

@main.route('/secret')
@login_required
@otp_required
@admin_required
def admin():
    members = User.query.all()
    form = UserToggleForm()
    return render_template('admin.html', members=members, form = form)


# Route for enabling/disabling user accounts (admin only)
@main.route('/admin/user/<int:user_id>/toggle_status', methods=['POST'])
@login_required
@otp_required
def toggle_user_status(user_id):
    if not current_user.is_admin:
        abort(403)  # Only admin can access this route

    user = User.query.get_or_404(user_id)
    if user == current_user:
        flash('Cannot disable your own account.', 'danger')
    else:
        user.is_blocked = not user.is_blocked
        user.save()
        logger.info('User status toggled by admin. User ID: {}, Status: {}'.format(user_id, user.is_active))
        flash('User account status updated.', 'success')

    return redirect(url_for('main.admin'))  # Update the route name based on your admin dashboard route


# Route for submitting feedback
# @limiter.limit("2000/minute")  # Rate limit: maximum 2 requests per minute
@main.route('/feedback', methods=['GET', 'POST'])
@login_required
@otp_required
def feedback():
    if not current_user.is_active or not current_user.is_verified:
        abort(403)  # User is not allowed to submit feedback

    form = FeedbackForm()
    if form.validate_on_submit():
        # Handle file upload
        file = form.file.data
        if file:

                        # Check the MIME type of the file using python-magic
            mime = magic.Magic(mime=True)
            mimetype = mime.from_buffer(file.read())
            if mimetype != 'application/pdf':
                flash("File is not a valid PDF", 'danger')
                return redirect(url_for('main.dashboard'))
            file.seek(0)

            
            # # Save the file data to a BytesIO object
            # file_data = BytesIO(file.read())
            # # Scan the file for viruses
            # scan_results = scan_file_virustotal(file_data)


            #     # Check the response from the VirusTotal API
            # if scan_results['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            #     flash('Malicious File Detected', 'danger')
            #     return redirect(url_for('main.dashboard'))

            # Save the file
            with app.app_context():
                filename = uuid.uuid4().hex + '.pdf'
                real_filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename),buffer_size=None)
        else:
            filename = None
            real_filename = None

        # Create a new Feedback instance
        feedback = Feedback(
            comment=form.comment.data,
            file=filename,
            real_file_name=real_filename,
            user_id=current_user.id
        )

        feedback.save()
        logger.info('New feedback submitted by user: {}'.format(current_user.username))
        flash('Feedback submitted successfully.', 'success')
        return redirect(url_for('main.dashboard'))
    if form.errors:
        errors = form.errors
        for key, val in errors.items():
            for err in val:
                flash(err, 'danger')
    return redirect(url_for('main.dashboard'))




# Route for editing feedback
@main.route('/feedback/edit/<int:feedback_id>', methods=['GET', 'POST'])
@login_required
@otp_required
def edit_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)

    # Check if the feedback belongs to the current user
    if feedback.user != current_user:
        abort(403)  # User is not allowed to edit other users' feedbacks

    form = FeedbackForm()   
    if request.method == 'GET':
        return render_template('edit_feedback.html', form=form, feedback=feedback)

    if form.validate_on_submit():
        # Handle file upload
        file = form.file.data
        if file:


            # Delete the old file, if any
            if feedback.file:
                mime = magic.Magic(mime=True)
                mimetype = mime.from_buffer(file.read())
                if mimetype != 'application/pdf':
                    flash("File is not a valid PDF", 'danger')
                    return redirect(url_for('main.dashboard'))
                file.seek(0)
                
                with app.app_context():
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], feedback.file)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)

            # Save the new file
            filename = uuid.uuid4().hex + '.pdf'
            real_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = feedback.file
            real_filename = feedback.real_file_name

        feedback.comment = form.comment.data
        feedback.file = filename
        feedback.real_file_name = real_filename
        feedback.save()

        logger.info('Feedback edited by user: {}'.format(current_user.username))
        flash('Feedback updated successfully.', 'success')
        return redirect(url_for('main.dashboard'))
    else:
        errors = form.errors
        for key, val in errors.items():
            for err in val:
                flash(err, 'danger')
    return render_template('edit_feedback.html', form=form, feedback=feedback)




# Route to serve the uploaded files
@main.route('/uploads/<filename>', methods=['GET'])
@login_required
@otp_required
def files_uploaded(filename):

    with app.app_context():
        uploads_dir = app.config.get('UPLOAD_FOLDER', 'uploads')# Path to the directory where the files are stored
        return send_from_directory(uploads_dir, filename)



@main.route('/feedback/delete/<int:feedback_id>', methods=['POST', ])
@login_required
@otp_required
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)

    # Check if the logged-in user owns the feedback
    if feedback.user_id != current_user.id and not current_user.is_admin:
        flash('You are not authorized to delete this feedback.', 'danger')
        return redirect(url_for('main.dashboard'))

    try:
        db.session.delete(feedback)
        if feedback.file:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], feedback.file))

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



# @limiter.limit("5/minute")
@main.route('/admin_login', methods=['POST', 'GET' ])
def honeypot():
    form = LoginForm()
    if form.validate_on_submit():
        flash('Password Incorrect!', 'warning')
        logger.info('Honeypot triggered')

         # Get the IP address of the request sender
        ip_address = request.remote_addr
        # Get the user agent (browser information)
        user_agent = request.user_agent.string
        # Get the request headers
        headers = request.headers

        # Log the information and save to DB
        logger.info(f'IP Address: {ip_address}')
        logger.info(f'User Agent: {user_agent}')
        logger.info(f'Headers: {headers}')

        # Save the information to DB
        honeypot = Honeypot(
            ip=ip_address,
            user_agent=user_agent,
            headers=str(headers)
        )
        honeypot.save()
    return render_template('login.html', form=form)


@main.route('/honeypots', methods=['GET', ])
@login_required
@otp_required
@admin_required
def view_honeypot():
    honeypots = Honeypot.query.all()
    return render_template('honeypot.html', honeypots=honeypots)
