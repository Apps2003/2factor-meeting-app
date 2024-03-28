import json
import os.path
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from random import randint
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, login_required, current_user, logout_user

import bcrypt
import hashlib

import cv2
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)
app.config['SECRET_KEY'] = "my-secrets"


if not os.path.isfile('config.json'):
    print("Error: 'config.json' file not found.")

# Load email configuration from config.json
with open('config.json', 'r') as f:
    params = json.load(f)['params']

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = params['gmail-user']
app.config['MAIL_PASSWORD'] = params['gmail-password']
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# Initialize Flask-Mail
mail = Mail(app)

# Generate OTP
otp = randint(1000, 9999)  # Ensure OTP is 4 digits

# Database Configuration
db = SQLAlchemy()
app.config['SECRET_KEY'] = "my-secrets"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///video-meeting.db"
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Register.query.get(int(user_id))


class Register(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def is_active(self):
        return True

    def get_id(self):
        return str(self.id)

    def is_authenticated(self):
        return True
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8')) 

with app.app_context():
    db.create_all()


class RegistrationForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired()])
    first_name = StringField(label="First Name", validators=[DataRequired()])
    last_name = StringField(label="Last Name", validators=[DataRequired()])
    username = StringField(label="Username", validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=8, max=20)])


class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])


def send_email_notification():
    # Email configuration
    sender_email = "21301066aparna@viva-technology.org"
    receiver_email = "aparnarane2003@gmail.com"
    password = "Aparna1066"
    
    # Create message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "Suspicious Activity Detected"
    body = "Suspicious activity was detected during the meeting."
    message.attach(MIMEText(body, "plain"))
    
    # Send email
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())



from flask import redirect, url_for

def detect_suspicious_activity():
    # Load the cascade
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

    # Start video capture
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)

    # Track time when the detection process started
    start_time = datetime.now()

    # Track time when last face was detected
    last_face_detected_time = datetime.now()

    # Track whether a face is detected within the desired time
    face_detected_within_time = False

    while True:
        # Capture frame-by-frame
        ret, frame = cap.read()

        # Convert to grayscale
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # Detect faces
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

        # Draw rectangle around the faces
        for (x, y, w, h) in faces:
            cv2.rectangle(frame, (x, y), (x+w, y+h), (255, 0, 0), 2)

        # Display the resulting frame
        cv2.imshow('frame', frame)

        # Check if face is detected
        if len(faces) > 0:
            last_face_detected_time = datetime.now()
            # Calculate the time taken to detect the face
            detection_time = datetime.now() - start_time
            if detection_time.total_seconds() < 30:
                # If face is detected within the desired time, set the flag to True
                face_detected_within_time = True

        # Check if no face is detected for a certain duration (e.g., 5 seconds)
        if datetime.now() - last_face_detected_time > timedelta(seconds=5):
            print("Suspicious activity detected: No face detected")
            send_email_notification()
            return redirect(url_for("dashboard"))  # Redirect to dashboard if no face is detected

        # Exit loop if 'q' is pressed
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

        # If face is detected within the desired time, release the capture and load the meeting page
        if face_detected_within_time:
            cap.release()
            cv2.destroyAllWindows()
            return redirect(url_for("meeting"))

    # Release the capture
    cap.release()
    cv2.destroyAllWindows()





@app.route("/")
def home():
    return redirect(url_for("email"))


@app.route("/email", methods=["POST", "GET"])
def email():
    return render_template('email.html', msg="")


@app.route('/verify', methods=["POST"])
def verify():
    # Get email address from form
    gmail = request.form['email']

    # Create and send email message with OTP
    msg = Message('OTP', sender='21301066aparna@viva-technology.org', recipients=[gmail])
    msg.body = str(otp)
    mail.send(msg)

    return render_template("verify.html")


@app.route('/validate', methods=["POST"])
def validate():
    userotp = request.form['otp']
    if otp == int(userotp):
        flash("Email Verified successfully")
        return redirect(url_for("dashboard"))
    return render_template('email.html', msg='Not verified!')


@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = Register.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for("dashboard"))
    flash("Please enter correct details!", "info")
    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out successfully!", "info")
    return redirect(url_for("login"))


@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegistrationForm()
    if request.method == "POST" and form.validate_on_submit():
        new_user = Register(
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            password=form.password.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Account created Successfully! <br>You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", first_name=current_user.first_name, last_name=current_user.last_name)


@app.route("/meeting")
@login_required
def meeting():
    detect_suspicious_activity()
    username = current_user.username
    return render_template("meeting.html", username=username)


@app.route("/join", methods=["GET", "POST"])
@login_required
def join():
    if request.method == "POST":
        room_id = request.form.get("roomID")
        detect_suspicious_activity()
        return redirect(f"/meeting?roomID={room_id}")

    return render_template("join.html")


if __name__ == "__main__":
    app.run(debug=True)
