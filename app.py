from flask import Flask, current_app,request, session, jsonify, url_for, render_template, send_from_directory, send_file
from flask_cors import CORS
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from flask_caching import Cache
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import os
import logging
from celery import Celery
from celery.schedules import crontab
from redis import Redis
import csv
from models import *
import re
from flask_wtf.csrf import CSRFProtect, generate_csrf


app = Flask(__name__, static_folder='dist', static_url_path='')
CORS(app, supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///datab.sqlite3.db'
app.config['SECRET_KEY'] = '1234'
app.config['SECURITY_PASSWORD_SALT'] = 'passwordsalt'

user_datastore = SQLAlchemyUserDatastore(datab, User, None)
security = Security(app) 

cache = Cache()

app.config['CACHE_TYPE'] = 'redis'
app.config['CACHE_KEY_PREFIX'] = 'myapp:'  # Prefix for cache keys
app.config['CACHE_REDIS_URL'] = "redis://localhost:6379/0"
app.config['CACHE_DEFAULT_TIMEOUT'] = 300


cache.init_app(app)


datab.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve(path):
    full_path = os.path.join(app.static_folder, path)
    if os.path.exists(full_path):
        return send_from_directory(app.static_folder, path)
    else:
        logging.warning(f"File not found: {full_path}")
        return send_from_directory(app.static_folder, 'index.html')

app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 1025
app.config['MAIL_DEFAULT_SENDER'] = 'no-reply@example.com'

# Celery (background task queue)
app.config['CELERY_BROKER_URL'] = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
app.config['result_backend'] = os.environ.get('result_backend', 'redis://localhost:6379/0')

def make_celery(app):
    celery = Celery(app.import_name, broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
    return celery

celery = make_celery(app)

mail = Mail(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()


    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    reach = data.get('reach')
    niche = data.get('niche')
    name = data.get('name')
    email = data.get('email')
    phone_number = data.get('phone_number')
    preferred_reminder_time = data.get('preferred_reminder_time', '18:00')

    if not username or not password or not role or not name or not phone_number:
        return jsonify({'success': False, 'message': 'Please fill in all required fields.'})

    if email and not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'success': False, 'message': 'Invalid email format.'})

    if role == 'influencer' and (reach is None or reach < 1000):
        return jsonify({'success': False, 'message': 'Influencer reach must be at least 1000.'})

    approved = True if role != 'sponsor' else False  # Sponsors are unapproved by default

    hashed_password = generate_password_hash(password)

    try:
        user = User(
            username=username,
            password=hashed_password,
            role=role,
            reach=reach if reach else 0,
            niche=niche if niche else 'general',
            name=name,
            email=email,
            phone_number=phone_number,
            preferred_reminder_time=preferred_reminder_time,
            approved=approved,
            fs_uniquifier=email 
        )
        datab.session.add(user)
        datab.session.commit()
        return jsonify(message="Registration successful"), 200
    except Exception as e:
        print(e)
        datab.session.rollback()
        return jsonify({'success': False, 'message': 'Registration failed.'})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Invalid JSON data'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required.'}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
       
        if user.role == 'sponsor' and not user.approved:
            return jsonify({'success': False, 'message': 'Your account is pending approval. Please contact admin.'}), 403

        
        if user.role == 'influencer' and user.flagged:
            return jsonify({'success': False, 'message': 'Your account is flagged. Contact Support'}), 403

     
        login_user(user)
        session['user_id'] = user.id

        return jsonify({
            'success': True,
            'role': user.role,
            'approved': user.approved if user.role == 'sponsor' else True  # Only include approval status for sponsors
        }), 200

    return jsonify({'success': False, 'message': 'Login unsuccessful. Please check Username and Password'}), 401

# Admin Dashboard Route
@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
@cache.cached(timeout=5)
def admin_dashboard():
    if 'user_id' not in session:
        return jsonify({'message': 'Please log in again.'}), 403

    if request.method == 'POST':
        data = request.get_json()
        if 'approve_sponsor' in data:
            return approve_sponsor(data['approve_sponsor'])
        return handle_flagging()

    active_users_count = User.query.count()
    public_campaigns_count = Campaign.query.filter_by(visibility='public').count()
    private_campaigns_count = Campaign.query.filter_by(visibility='private').count()
    ad_requests_count = AdRequest.query.count()
    flagged_users_count = User.query.filter_by(flagged=True).count()
    flagged_campaigns_count = Campaign.query.filter_by(flagged=True).count()

    histogram_data = [
        ('Active Users', active_users_count),
        ('Public Campaigns', public_campaigns_count),
        ('Private Campaigns', private_campaigns_count),
        ('Ad Requests', ad_requests_count),
        ('Flagged Users', flagged_users_count),
        ('Flagged Campaigns', flagged_campaigns_count)
    ]
    
    maxi = max(active_users_count, public_campaigns_count, private_campaigns_count,
               ad_requests_count, flagged_users_count, flagged_campaigns_count)

    campaigns = Campaign.query.all()
    ad_requests = AdRequest.query.all()

    unapproved_sponsors = User.query.filter_by(role='sponsor', approved=False).all()

    return jsonify({
        'user': current_user.username,
        'active_users_count': active_users_count,
        'public_campaigns_count': public_campaigns_count,
        'private_campaigns_count': private_campaigns_count,
        'ad_requests_count': ad_requests_count,
        'flagged_users_count': flagged_users_count,
        'flagged_campaigns_count': flagged_campaigns_count,
        'unapproved_sponsors': [sponsor.username for sponsor in unapproved_sponsors],
        'histogram_data': histogram_data,
        'maxi': maxi,
        'campaigns': [campaign.name for campaign in campaigns],
        'ad_requests': [ad_request.ad_request_id for ad_request in ad_requests]
    }), 200

def handle_flagging():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400
    
    username = data.get('username')
    name = data.get('name')

    if username:
        return flag_user_by_username(username)
    elif name:
        return flag_campaign(name)
    else:
        return jsonify({'message': 'No user or campaign selected for flagging'}), 400

def flag_user_by_username(username):
    if username == current_user.username:
        return jsonify({'message': 'Error: You cannot flag yourself.'}), 403

    user_to_flag = User.query.filter_by(username=username).first()
    if user_to_flag:
        if user_to_flag.role == 'sponsor':
            return jsonify({'message': 'Error: Sponsors cannot be flagged.'}), 403
        
        user_to_flag.flagged = True
        datab.session.commit()
        return jsonify({'message': f'User {username} flagged successfully.'}), 200

    return jsonify({'message': 'Error: User not found.'}), 404

def flag_campaign(name):
    campaign_to_flag = Campaign.query.filter_by(name=name).first()
    if campaign_to_flag:
        campaign_to_flag.flagged = True
        datab.session.commit()
        return jsonify({'message': f'Campaign {campaign_to_flag.name} flagged successfully.'}), 200

    return jsonify({'message': 'Error: Campaign not found.'}), 404

def approve_sponsor(username):
    user_to_approve = User.query.filter_by(username=username, role='sponsor').first()
    if user_to_approve:
        user_to_approve.approved = True
        datab.session.commit()
        return jsonify({'success': True, 'message': f'Sponsor {username} approved successfully.'}), 200
    return jsonify({'success': False, 'message': 'Sponsor not found.'}), 404


@app.route('/sponsor_dashboard', methods=['GET'])
@login_required
@cache.cached(timeout=5)
def sponsor_dashboard():
    if 'user_id' not in session or session['user_id'] != current_user.id:
        return jsonify({'message': 'Please log in again.'}), 403

    if current_user.role != 'sponsor':
        return jsonify({'message': 'Only sponsors can access this page'}), 403

    sponsor_campaigns = Campaign.query.filter_by(sponsor_id=current_user.id).all()
    
    return jsonify({
        'user': {
            'username': current_user.username,
            'role': current_user.role,
        },
        'campaigns': [{
            'campaign_id': campaign.campaign_id,
            'name': campaign.name,
            'description': campaign.description,
            'start_date': campaign.start_date,
            'end_date': campaign.end_date,
            'budget': campaign.budget,
            'visibility': campaign.visibility,
            'ad_requests': [{
                'ad_request_id': ad_request.ad_request_id,
                'username': ad_request.username,
                'messages': ad_request.messages,
                'payment_details': ad_request.payment_details,
                'requirements': ad_request.requirements,
                'payment_amount': ad_request.payment_amount,
                'status': ad_request.status
            } for ad_request in campaign.ad_requests]
        } for campaign in sponsor_campaigns]
    }), 200


@app.route('/influencer_dashboard')
@login_required
@cache.cached(timeout=5)  # Cache for 300secs
def influencer_dashboard():
    user_id = session.get('user_id')
    
    if user_id != current_user.id:
        return jsonify({'message': 'Please log in again.'}), 403

    influencer = User.query.filter_by(id=current_user.id).first()
    if not influencer:
        return jsonify({'message': 'User not found.'}), 404

    username = current_user.username
    influencer_niche = influencer.niche or "Not specified"
    influencer_reach = influencer.reach or 0
    influencer_name = influencer.name or "Anonymous"
    
    active_campaigns = Campaign.query.filter_by(visibility='public', flagged=False).count()
    pending_requests = AdRequest.query.filter_by(status='pending', username=current_user.username).count()
    ongoing_negotiations = AdRequest.query.filter_by(status='Negotiated', username=current_user.username).count()
    ad_requests = AdRequest.query.filter_by(username=current_user.username).all()
    
    ad_requests_list = [{'id': ad_request.ad_request_id, 'details': ad_request.messages} for ad_request in ad_requests]
    
    return jsonify({
        'username': username,
        'niche': influencer_niche,
        'reach': influencer_reach,
        'name': influencer_name,
        'active_campaigns': active_campaigns,
        'pending_requests': pending_requests,
        'ongoing_negotiations': ongoing_negotiations,
        'ad_requests': ad_requests_list
    }), 200



@app.route('/create_campaign', methods=['POST'])
@login_required
@cache.cached(timeout=300)
def create_campaign():
    if 'user_id' not in session:
        return jsonify({'message': 'Please log in again.'}), 403
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    name = data.get('name')
    description = data.get('description')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    budget = data.get('budget')
    visibility = data.get('visibility')

    try:
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid date format.'}), 400

    if not name or len(name) < 2 or len(name) > 150:
        return jsonify({'success': False, 'message': 'Campaign name must be between 2 and 150 characters.'}), 400
    if end_date < start_date:
        return jsonify({'success': False, 'message': 'End date should be greater than start date.'}), 400
    if budget < 0:
        return jsonify({'success': False, 'message': 'Budget must be greater than 0.'}), 400

    existing_campaign = Campaign.query.filter_by(name=name).first()
    if existing_campaign:
        return jsonify({'success': False, 'message': 'Campaign name already taken. Please choose a different one.'}), 400

    campaign = Campaign(
        name=name,
        description=description,
        start_date=start_date,
        end_date=end_date,
        budget=budget,
        visibility=visibility,
        sponsor_id=current_user.id
    )
    datab.session.add(campaign)
    datab.session.commit()
    cache.clear()
    return jsonify({'success': True, 'message': 'Campaign created successfully'}), 201

@app.route('/update_campaign/<int:campaign_id>', methods=['POST'])
@login_required
def update_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.sponsor_id != current_user.id:
        return jsonify({'success': False, 'message': 'You are not authorized to update this campaign.'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    name = data.get('name')
    description = data.get('description')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    budget = data.get('budget')
    visibility = data.get('visibility')

    # Convert date strings to datetime.date objects
    try:
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid date format.'}), 400

    if end_date <= start_date:
        return jsonify({'success': False, 'message': 'End date must be after start date.'}), 400

    campaign.name = name
    campaign.description = description
    campaign.start_date = start_date
    campaign.end_date = end_date
    campaign.budget = budget
    campaign.visibility = visibility

    datab.session.commit()
    cache.clear()
    return jsonify({'success': True, 'message': 'Campaign updated successfully.'}), 200

@app.route('/delete_campaign/<int:campaign_id>', methods=['DELETE'])
@login_required
def delete_campaign(campaign_id):
    if 'user_id' not in session or session['user_id'] != current_user.id:
        return jsonify({'message': 'Please log in again.'}), 403
    
    campaign = Campaign.query.get_or_404(campaign_id)
    
    if campaign.sponsor_id != current_user.id:
        return jsonify({'message': 'You are not authorized to delete this campaign.'}), 403
    
    datab.session.delete(campaign)
    datab.session.commit()
    
    return jsonify({'success': True, 'message': 'Campaign deleted successfully.'}), 200

@app.route('/create_ad_request/<int:campaign_id>', methods=['POST'])
@login_required
def create_ad_request(campaign_id):
    user_id = session.get('user_id')
    if user_id != current_user.id:
        return jsonify({'message': 'Please log in again.'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    campaign = Campaign.query.get_or_404(campaign_id)

    ad_request_amount = float(data.get('payment_amount'))
    if ad_request_amount < 0:
        return jsonify({'message': 'Ad request amount must be greater than or equal to zero.'}), 400
    elif ad_request_amount > campaign.budget:
        return jsonify({'message': 'Ad request amount should not exceed the campaign budget.'}), 400

    username = data.get('username')

    # Check if the influencer exists and has the role of "influencer"
    influencer = User.query.filter_by(username=username, role='influencer').first()
    if not influencer:
        return jsonify({'message': 'Username does not exist or is not an influencer.'}), 400

    ad_request = AdRequest(
        campaign_id=campaign_id,
        username=username,
        messages=data.get('messages'),
        payment_details=data.get('payment_details'),
        requirements=data.get('requirements'),
        payment_amount=ad_request_amount,
        status=data.get('status')
    )
    datab.session.add(ad_request)
    datab.session.commit()
    cache.clear()
    return jsonify({'success': True, 'message': 'Ad request created successfully.'}), 201

@app.route('/update_ad_request/<int:ad_request_id>', methods=['POST'])
@login_required
def update_ad_request(ad_request_id):
    user_id = session.get('user_id')
    if user_id != current_user.id:
        return jsonify({'message': 'Please log in again.'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    ad_request = AdRequest.query.get_or_404(ad_request_id)
    ad_request_amount = float(data.get('payment_amount'))
    campaign = Campaign.query.get(ad_request.campaign_id)

    if ad_request_amount < 0:
        return jsonify({'message': 'Ad request amount must be greater than or equal to zero.'}), 400
    elif ad_request_amount > campaign.budget:
        return jsonify({'message': 'Ad request amount should not exceed the campaign budget.'}), 400

    username = data.get('username')

    influencer = User.query.filter_by(username=username, role='influencer').first()
    if not influencer:
        return jsonify({'message': 'Username does not exist or is not an influencer.'}), 400

    ad_request.username = username
    ad_request.messages = data.get('messages')
    ad_request.payment_details = data.get('payment_details')
    ad_request.requirements = data.get('requirements')
    ad_request.payment_amount = ad_request_amount
    ad_request.status = data.get('status')

    datab.session.commit()
    cache.clear()
    return jsonify({'success': True, 'message': 'Ad request updated successfully.'}), 200

@app.route('/delete_ad_request/<int:ad_request_id>', methods=['DELETE'])
@login_required
def delete_ad_request(ad_request_id):
    user_id = session.get('user_id')
    if user_id != current_user.id:
        return jsonify({'message': 'Please log in again.'}), 403
    
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    
    datab.session.delete(ad_request)
    datab.session.commit()
    cache.clear()
    return jsonify({'message': 'Ad request deleted successfully.'}), 200


@app.route('/search_influencers', methods=['POST'])
@login_required
def search_influencers():
    user_id = current_user.id

    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    name_keyword = data.get('name', '').strip()
    reach_keyword = data.get('reach', None)

    query = User.query.filter_by(role='influencer')

    if name_keyword and not (2 <= len(name_keyword) <= 150):
        return jsonify({'message': 'Influencer name must be between 2 and 150 characters.'}), 400

    if reach_keyword is not None and reach_keyword < 1000:
        return jsonify({'message': 'Reach must be greater than or equal to 1000.'}), 400

    if name_keyword:
        query = query.filter(User.name.ilike(f'%{name_keyword.lower()}%'))
    
    if reach_keyword is not None:
        query = query.filter(User.reach >= reach_keyword)

    influencers = query.all()
    return jsonify({
        'influencers': [{'username': influencer.username, 'name': influencer.name, 'reach': influencer.reach, 'niche': influencer.niche} for influencer in influencers]
    }), 200

@app.route('/view_campaigns', methods=['GET', 'POST'])
def view_campaigns():
    if request.method == 'POST':
        name_keyword = request.json.get('name', '').strip().lower()
        
        campaigns = Campaign.query.filter(
            Campaign.name.ilike(f'%{name_keyword}%'),
            Campaign.visibility == 'public',
            Campaign.flagged == False
        ).all()
    else:
        
        campaigns = Campaign.query.filter_by(visibility='public', flagged=False).all()

    return jsonify({
        'campaigns': [{
            'name': campaign.name,
            'description': campaign.description,
            'budget': campaign.budget,
            'visibility': campaign.visibility,
            'start_date': campaign.start_date.isoformat(),
            'end_date': campaign.end_date.isoformat()
        } for campaign in campaigns]
    }), 200


@app.route('/view_ad_requests/<username>', methods=['GET'])
def view_ad_requests(username):
    influencer = User.query.filter_by(username=username).first()
    if not influencer:
        return jsonify({'success': False, 'message': 'Influencer not found.'}), 404
    ad_requests = AdRequest.query.filter_by(username=username).all()
    ad_requests_data = [{
        'ad_request_id': ad_request.ad_request_id,
        'campaign': {'name': ad_request.campaign.name} if ad_request.campaign else {'name': 'N/A'},
        'messages': ad_request.messages,
        'requirements': ad_request.requirements,
        'payment_amount': ad_request.payment_amount,
        'status': ad_request.status
    } for ad_request in ad_requests]
    return jsonify({
        'success': True,
        'influencer': {
            'username': influencer.username,
            'name': influencer.name,
            'reach': influencer.reach,
            'niche': influencer.niche
        },
        'ad_requests': ad_requests_data
    }), 200

@app.route('/accept_ad_request/<int:ad_request_id>', methods=['POST'])
def accept_ad_request(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    if ad_request.status != 'Accepted':
        payment_details = request.json.get('payment_details')
        if payment_details:
            ad_request.payment_details = payment_details
            ad_request.status = 'Accepted'
            datab.session.commit()
            return jsonify({'message': 'Ad request accepted successfully.'}), 200
        else:
            return jsonify({'message': 'Payment details are required.'}), 400
    else:
        return jsonify({'message': 'Ad request has already been accepted.'}), 400

@app.route('/reject_ad_request/<int:ad_request_id>', methods=['POST'])
def reject_ad_request(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    if ad_request.status != 'Rejected':
        ad_request.status = 'Rejected'
        datab.session.commit()
        return jsonify({'message': 'Ad request rejected successfully.'}), 200
    else:
        return jsonify({'message': 'Ad request has already been rejected.'}), 400

@app.route('/negotiate_ad_request/<int:ad_request_id>', methods=['POST'])
def negotiate_ad_request(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    if ad_request.status != 'Negotiated':
        messages = request.json.get('messages')
        if messages:
            ad_request.messages = messages
            ad_request.status = 'Negotiated'
            datab.session.commit()
            return jsonify({'message': 'Ad request negotiated successfully.'}), 200
        else:
            return jsonify({'message': 'Negotiation messages are required.'}), 400
    else:
        return jsonify({'message': 'Ad request has already been negotiated.'}), 400


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_id = session.get('user_id')
    if user_id != current_user.id:
        return jsonify({'message': 'Please log in again.'}), 403
    
    influencer = User.query.get(current_user.id)

    if request.method == 'POST':
        if request.json.get('delete_confirm'):
            datab.session.delete(influencer)
            datab.session.commit()
            logout_user()
            return jsonify({'message': 'Profile deleted successfully.'}), 200

        niche = request.json.get('niche')
        reach = request.json.get('reach')
        username = request.json.get('username')
        password = request.json.get('password')

        try:
            if niche:
                influencer.niche = niche
            if reach:
                influencer.reach = reach
            if username:
                influencer.username = username
            if password:
                influencer.set_password(password)

            datab.session.commit()
            return jsonify({'message': 'Profile updated successfully.'}), 200
        except Exception as e:
            datab.session.rollback()
            return jsonify({'message': 'Updation failed, username taken or invalid data.'}), 400

    return jsonify({
        'niche': influencer.niche,
        'reach': influencer.reach,
        'username': influencer.username,
    }), 200


@app.route('/sponsor_edit_profile', methods=['POST'])
@login_required
def sponsor_edit_profile():
    user_id = current_user.id
    data = request.get_json()

    if not data:
        return jsonify({'message': 'No data provided'}), 400
    
    if data.get('delete_confirm'):
        sponsor = User.query.filter_by(id=user_id).first()
        if not sponsor:
            return jsonify({'message': 'User not found.'}), 404
        
        datab.session.delete(sponsor)
        datab.session.commit()
        logout_user()
        return jsonify({'message': 'Profile deleted successfully.'}), 200

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if username and not (2 <= len(username) <= 150):
        return jsonify({'message': 'Username must be between 2 and 150 characters.'}), 400

    if password and len(password) < 2:
        return jsonify({'message': 'Password must be at least 6 characters long.'}), 400

    sponsor = User.query.filter_by(id=user_id).first()
    if not sponsor:
        return jsonify({'message': 'User not found.'}), 404

    if username:
        sponsor.username = username
    if password:
        sponsor.set_password(password)

    datab.session.commit()
    return jsonify({'message': 'Profile updated successfully.'}), 200

@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully!'}), 200


# Celery Task:Daily Reminders
@celery.task(name='send_daily_reminders')
def send_daily_reminders(user_id):
    with app.app_context():
        user = User.query.get(user_id)
        
        if user and user.role == 'influencer':
            pending_requests = AdRequest.query.filter_by(username=user.username, status='pending').count()
            last_login = user.last_login or datetime.min
            
            if pending_requests > 0 or (datetime.now() - last_login) > timedelta(days=1):
                msg = Message(subject='Reminder: Pending Ad Requests', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[user.email])
                msg.body = "You have pending ad requests or haven't logged in recently. Please check your dashboard."
                try:
                    mail.send(msg)
                    app.logger.info(f"Sent daily reminder to {user.email}")
                except Exception as e:
                    app.logger.error(f"Failed to send daily reminder to {user.email}: {e}")

# Celery Task:Monthly Activity Reports
@celery.task(name='send_monthly_activity_reports')
def send_monthly_activity_reports():
    with app.app_context():
        users = User.query.filter_by(role='sponsor').all()
        for user in users:
            campaigns = Campaign.query.filter_by(sponsor_id=user.id).all()
            report_data = generate_activity_report(campaigns)
            
            msg = Message(subject='Monthly Activity Report', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[user.email])
            msg.html = report_data
            try:
                mail.send(msg)
                app.logger.info(f"Sent monthly report to {user.email}")
            except Exception as e:
                app.logger.error(f"Failed to send monthly report to {user.email}: {e}")

# Helper function to generate the activity report
def generate_activity_report(campaigns):
    report_html = "<h1>Monthly Activity Report</h1>"
    for campaign in campaigns:
        report_html += f"<p>Campaign: {campaign.name}, Budget: {campaign.budget}, Status: {'Active' if not campaign.flagged else 'Flagged'}</p>"
    return report_html

# Celery Beat Schedule for Daily Reminders
@celery.task
def schedule_daily_reminders_for_users():
    users = User.query.filter_by(role='influencer').all()
    for user in users:
        preferred_time = user.preferred_reminder_time or '18:00'  # Default to 6:00 PM
        hour, minute = map(int, preferred_time.split(':'))
        # Scheduling Celery task for daily reminders at the user's preferred time
        eta = datetime(datetime.now().year, datetime.now().month, datetime.now().day, hour, minute)
        send_daily_reminders.apply_async(args=[user.id], eta=eta)

# Celery Beat Schedule (Run daily reminder task for all influencers)
celery.conf.beat_schedule = {
    'schedule-daily-reminders': {
        'task': 'app.schedule_daily_reminders_for_users',
        'schedule': crontab(minute=0, hour=0),  # This runs once every day at midnight to schedule reminders for users
    },
}

# Celery Beat Schedule (Run monthly report task)
celery.conf.beat_schedule.update({
    'send-monthly-reports': {
        'task': 'app.send_monthly_activity_reports',
        'schedule': crontab(minute=0, hour=0, day_of_month=1),  # Runs at midnight on the 1st of each month
    },
})

@app.route('/test-send-email')
def test_send_email():
    user = User.query.first()

    if user:
        msg = Message(subject='Test Email', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[user.email])
        msg.body = "This is a test email."

        try:
            mail.send(msg)
            return "Test email sent!", 200
        except Exception as e:
            app.logger.error(f"Failed to send test email: {e}")
            return f"Failed to send test email: {e}", 500
    else:
        return "No user found!", 404
    
#Celery Task: Send Daily Reminders
@celery.task(name='send_daily_reminders')
def send_daily_reminders(user_id):
    with app.app_context():
        user = User.query.get(user_id)
        if user:
            pending_requests = AdRequest.query.filter_by(username=user.username, status='pending').count()
            last_login = user.last_login or datetime.min
            
            if pending_requests > 0 or (datetime.now() - last_login) > timedelta(days=1):
                msg = Message(subject='Reminder: Pending Ad Requests', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[user.email])
                msg.body = "You have pending ad requests or haven't logged in recently. Please check your dashboard."
                try:
                    mail.send(msg)
                    app.logger.info(f"Sent daily reminder to {user.email}")
                except Exception as e:
                    app.logger.error(f"Failed to send daily reminder to {user.email}: {e}")
        else:
            app.logger.error(f"User with ID {user_id} not found.")

# Route to manually trigger the task at a specific time
@app.route('/trigger-send-reminder/<int:user_id>/<time>', methods=['GET'])
def trigger_send_reminder(user_id, time):
    try:
        # Parse the time argument (format: HH:MM)
        hour, minute = map(int, time.split(':'))
        
        # Get the current date and create a datetime object for the target time
        now = datetime.now()
        target_time = datetime(now.year, now.month, now.day, hour, minute)
        
        # If the target time has already passed for today, schedule for the next day
        if target_time < now:
            target_time += timedelta(days=1)
        
        # Trigger the Celery task at the specific time
        send_daily_reminders.apply_async(args=[user_id], eta=target_time)

        return f"Reminder task has been scheduled for user ID {user_id} at {target_time.strftime('%H:%M')}."
    
    except ValueError:
        return jsonify({'error': 'Invalid time format. Use HH:MM.'}), 400
    except Exception as e:
        app.logger.error(f"Error scheduling reminder for user ID {user_id}: {e}")
        return jsonify({'error': 'Failed to schedule reminder task.'}), 500

# Celery Beat Schedule (Run every day at midnight)
celery.conf.beat_schedule = {
    'export-campaigns-csv': {
        'task': 'app.export_campaigns_to_csv',
        'schedule': crontab(minute=0, hour=0),  # This will run the task every day at midnight
        'args': (1, 'test_sponsor')  # Replace with sponsor_id and username as needed
    },
}

# Celery Task for exporting campaigns to CSV
@celery.task
def export_campaigns_to_csv(sponsor_id, username):
    try:
        sponsor = User.query.filter_by(id=sponsor_id, role='sponsor').first()
        
        if not sponsor:
            logging.error(f"Sponsor with ID {sponsor_id} not found.")
            return {'message': 'Sponsor not found'}, 404

        sponsor_campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()

        campaign_data = [{
            'campaign_id': campaign.campaign_id,
            'name': campaign.name,
            'description': campaign.description,
            'start_date': campaign.start_date,
            'end_date': campaign.end_date,
            'budget': campaign.budget,
            'visibility': campaign.visibility,
            'ad_requests': [{
                'ad_request_id': ad_request.ad_request_id,
                'username': ad_request.username,
                'messages': ad_request.messages,
                'payment_details': ad_request.payment_details,
                'requirements': ad_request.requirements,
                'payment_amount': ad_request.payment_amount,
                'status': ad_request.status
            } for ad_request in campaign.ad_requests]
        } for campaign in sponsor_campaigns]

        # Start exporting to CSV
        file_path = os.path.join(current_app.root_path, f'{username}_campaigns.csv')
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Campaign ID', 'Name', 'Description', 'Start Date', 'End Date', 'Budget',
                             'Visibility', 'Ad Request ID', 'Username', 'Messages',
                             'Payment Details', 'Requirements', 'Payment Amount', 'Status'])

            for campaign in campaign_data:
                for ad_request in campaign['ad_requests']:
                    writer.writerow([ 
                        campaign['campaign_id'],
                        campaign['name'],
                        campaign['description'],
                        campaign['start_date'],
                        campaign['end_date'],
                        campaign['budget'],
                        campaign['visibility'],
                        ad_request['ad_request_id'],
                        ad_request['username'],
                        ad_request['messages'],
                        ad_request['payment_details'],
                        ad_request['requirements'],
                        ad_request['payment_amount'],
                        ad_request['status']
                    ])
        
        logging.info(f"Export completed. File available at: {file_path}")
        return {'file_path': file_path, 'message': 'CSV export completed.'}, 200

    except Exception as e:
        logging.error(f"Error during CSV export: {e}", exc_info=True)
        return {'message': 'Failed to export CSV.'}, 500


# Route for exporting CSV manually (for testing)
@app.route('/export_csv', methods=['GET'])
def export_csv():
    if current_user.role != 'sponsor':
        return jsonify({'message': 'Only sponsors can access this route'}), 403

    # Fetch the sponsor's campaigns
    sponsor_campaigns = Campaign.query.filter_by(sponsor_id=current_user.id).all()

    campaign_data = [{
        'campaign_id': campaign.campaign_id,
        'name': campaign.name,
        'description': campaign.description,
        'start_date': campaign.start_date,
        'end_date': campaign.end_date,
        'budget': campaign.budget,
        'visibility': campaign.visibility,
        'ad_requests': [{
            'ad_request_id': ad_request.ad_request_id,
            'username': ad_request.username,
            'messages': ad_request.messages,
            'payment_details': ad_request.payment_details,
            'requirements': ad_request.requirements,
            'payment_amount': ad_request.payment_amount,
            'status': ad_request.status
        } for ad_request in campaign.ad_requests]
    } for campaign in sponsor_campaigns]

    logging.info("Starting export to CSV...")
    try:
        # Save the CSV file in the root directory
        file_path = os.path.join(current_app.root_path, f'{current_user.username}_campaigns.csv')
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Campaign ID', 'Name', 'Description', 'Start Date', 'End Date', 'Budget',
                             'Visibility', 'Ad Request ID', 'Username', 'Messages',
                             'Payment Details', 'Requirements', 'Payment Amount', 'Status'])

            for campaign in campaign_data:
                for ad_request in campaign['ad_requests']:
                    writer.writerow([ 
                        campaign['campaign_id'],
                        campaign['name'],
                        campaign['description'],
                        campaign['start_date'],
                        campaign['end_date'],
                        campaign['budget'],
                        campaign['visibility'],
                        ad_request['ad_request_id'],
                        ad_request['username'],
                        ad_request['messages'],
                        ad_request['payment_details'],
                        ad_request['requirements'],
                        ad_request['payment_amount'],
                        ad_request['status']
                    ])
        logging.info(f"Export completed. File available at: {file_path}")
        return jsonify({'file_path': file_path, 'message': 'CSV export completed.'}), 200

    except Exception as e:
        logging.error(f"Error during CSV export: {e}", exc_info=True)
        return jsonify({'message': 'Failed to export CSV.'}), 500


# Route to download the CSV file
@app.route('/get_csv/<username>', methods=['GET'])
#@login_required
def get_csv(username):
    # Construct the file path
    file_path = os.path.join(current_app.root_path, f'{username}_campaigns.csv')
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return jsonify({'message': 'File not found.'}), 404


def create_database():
    # Create all tables if they don't exist
    datab.create_all()

    admin_user = User.query.filter_by(username='admin').first()

    if admin_user:
        datab.session.delete(admin_user)
        datab.session.commit()
        print("Existing admin user deleted.")

    admin_password = os.getenv('ADMIN_PASSWORD', 'abc')

    hashed_password = generate_password_hash(admin_password)

    default_email = 'admin@example.com'
    default_name = 'Administrator'
    default_phone_number = '1234567890'
    default_preferred_reminder_time = '18:00'
    default_role = 'admin'
    default_approved = True
    default_flagged = False

    fs_uniquifier_value = default_email

    admin_user = User(
        username='admin',
        password=hashed_password,
        role=default_role,
        email=default_email,
        name=default_name,
        phone_number=default_phone_number,
        preferred_reminder_time=default_preferred_reminder_time,
        approved=default_approved,
        flagged=default_flagged,
        fs_uniquifier=fs_uniquifier_value 
    )

    datab.session.add(admin_user)
    datab.session.commit()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    with app.app_context():
        create_database() 
    app.run(debug=True)