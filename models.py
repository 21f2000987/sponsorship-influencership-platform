from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_security import Security, SQLAlchemyUserDatastore,RoleMixin

datab = SQLAlchemy()

class User(UserMixin, datab.Model):
    __tablename__ = 'users'
    id = datab.Column(datab.Integer, primary_key=True)
    username = datab.Column(datab.String(150), nullable=False, unique=True)
    password = datab.Column(datab.String(150), nullable=False)
    role = datab.Column(datab.String(50), nullable=False)
    reach = datab.Column(datab.Integer)
    niche = datab.Column(datab.String(150))
    name = datab.Column(datab.String(100))
    email = datab.Column(datab.String(100))
    phone_number = datab.Column(datab.String(15))
    flagged = datab.Column(datab.Boolean, nullable=False, default=False)
    preferred_reminder_time = datab.Column(datab.String(5), default='18:00')
    approved = datab.Column(datab.Boolean, nullable=False, default=False)
    fs_uniquifier = datab.Column(datab.String(255), unique=True, nullable=False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.fs_uniquifier:
            self.fs_uniquifier = self.email

    # Password hashing functions
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def is_flagged(self):
        return self.flagged

    def __repr__(self):
        return (f"<User id={self.id}, username='{self.username}', role='{self.role}', "
                f"reach='{self.reach}', niche='{self.niche}', name='{self.name}', "
                f"email='{self.email}', phone_number='{self.phone_number}', "
                f"preferred_reminder_time='{self.preferred_reminder_time}', approved='{self.approved}'>")



class Campaign(datab.Model):
    __tablename__ = 'campaign'
    campaign_id = datab.Column(datab.Integer, primary_key=True)
    name = datab.Column(datab.String(128), nullable=False, unique=True)
    description = datab.Column(datab.Text, nullable=False)
    start_date = datab.Column(datab.DateTime, nullable=False, default=datetime.utcnow)
    end_date = datab.Column(datab.DateTime, nullable=False)
    budget = datab.Column(datab.Float, nullable=False)
    visibility = datab.Column(datab.String(10), nullable=False)
    sponsor_id = datab.Column(datab.Integer, datab.ForeignKey('users.id'), nullable=False)
    flagged = datab.Column(datab.Boolean, nullable=False, default=False)
    
    sponsor = datab.relationship("User", backref="campaigns")
    def __repr__(self):
        return f"<Campaign campaign_id={self.campaign_id}, name='{self.name}', " \
               f"description='{self.description}', start_date='{self.start_date}', " \
               f"end_date='{self.end_date}', budget={self.budget}, visibility='{self.visibility}', " \
               f"sponsor_id={self.sponsor_id}>"

class AdRequest(datab.Model):
    __tablename__ = 'ad_request'
    ad_request_id = datab.Column(datab.Integer, primary_key=True)
    campaign_id = datab.Column(datab.Integer, datab.ForeignKey('campaign.campaign_id'), nullable=False)
    username = datab.Column(datab.String(150), datab.ForeignKey('users.id'), nullable=False)
    messages = datab.Column(datab.Text)
    payment_details = datab.Column(datab.Text)
    requirements = datab.Column(datab.Text, nullable=False)
    payment_amount = datab.Column(datab.Float, nullable=False)
    status = datab.Column(datab.String(20), nullable=False)

    campaign = datab.relationship("Campaign", backref="ad_requests")
    influencer = datab.relationship("User", foreign_keys=[username], backref="ad_requests")

    def __repr__(self):
        return f"<AdRequest ad_request_id={self.ad_request_id}, campaign_id={self.campaign_id}, " \
               f"username='{self.username}', requirements='{self.requirements}', " \
               f"payment_amount={self.payment_amount}, messages='{self.messages}',status='{self.status}'>"
