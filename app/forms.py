import re
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, TextAreaField, FileField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_wtf.file import FileAllowed

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    captcha = RecaptchaField()
    submit = SubmitField('Login')

    def validate_username(self, field):
        if not re.match(r'^[a-zA-Z0-9]+$', field.data):
            raise ValidationError('Username must contain only letters and numbers.')


from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    captcha = RecaptchaField()

    submit = SubmitField('Register')

    def validate_password(self, password):
        # Check for strong password
        # Example criteria: At least 8 characters, containing both letters and numbers
        if len(password.data) < 8 or not any(char.isalpha() for char in password.data) or not any(char.isdigit() for char in password.data):
            raise ValidationError('Password must be at least 8 characters long and contain both letters and numbers.')

    def validate_confirm_password(self, confirm_password):
        # Check if confirm_password matches the password
        if confirm_password.data != self.password.data:
            raise ValidationError('Passwords do not match.')
        
    def validate_username(self, field):
        if not re.match(r'^[a-zA-Z0-9]+$', field.data):
            raise ValidationError('Username must contain only letters and numbers.')



class FeedbackForm(FlaskForm):
    comment = TextAreaField('Comment', validators = [DataRequired()])
    file = FileField(label = 'Optional File Upload. (Only PDF less than 5MB is accepted.)', validators = [FileAllowed(['pdf'], 'Only PDF files are accepted.')])
    submit = SubmitField('Comment')
    
    
    def validate_file(self, file):
        max_size = 5 * 1024 * 1024  # 5 MB
        if file.data and file.data.content_length > max_size:
            raise ValidationError('File size exceeds the allowed limit.')


class OTPForm(FlaskForm):
    otp = IntegerField('One Time Password', validators=[DataRequired()])
    submit = SubmitField('Verify')

class UserToggleForm(FlaskForm):
    user_id = IntegerField('user_id',validators=[DataRequired()])