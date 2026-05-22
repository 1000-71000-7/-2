from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='client')  # admin, operator, secretary, executor, client
    full_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(20))
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

    def is_operator(self):
        return self.role in ['admin', 'operator', 'secretary']

    def update_last_login(self):
        self.last_login = datetime.now()

    def __repr__(self):
        return f'<User {self.username}>'


class Department(db.Model):
    """Отделы администрации (ЖКХ, дороги, соцзащита и т.д.)"""
    __tablename__ = 'departments'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    head_name = db.Column(db.String(200))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    sort_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f'<Department {self.name}>'


class AppealType(db.Model):
    __tablename__ = 'appeal_types'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    sort_order = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<AppealType {self.name}>'


class AppealStatus(db.Model):
    __tablename__ = 'appeal_statuses'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    is_final = db.Column(db.Boolean, default=False)
    sort_order = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<AppealStatus {self.name}>'


class AppealComment(db.Model):
    """Комментарии к обращениям"""
    __tablename__ = 'appeal_comments'

    id = db.Column(db.Integer, primary_key=True)
    appeal_id = db.Column(db.Integer, db.ForeignKey('appeals.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    appeal = db.relationship('Appeal', backref=db.backref('comments', lazy=True, cascade='all, delete-orphan'))
    user = db.relationship('User', backref='comments')

    def __repr__(self):
        return f'<Comment {self.id} on Appeal {self.appeal_id}>'


class Employee(db.Model):
    """Сотрудники администрации (исполнители)"""
    __tablename__ = 'employees'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=False)
    position = db.Column(db.String(200), nullable=False)
    is_available = db.Column(db.Boolean, default=True)
    appointment_date = db.Column(db.Date, default=datetime.now().date)
    phone_work = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.now)

    # Рейтинговые показатели
    rating_score = db.Column(db.Float, default=0.0)
    completed_count = db.Column(db.Integer, default=0)
    overdue_count = db.Column(db.Integer, default=0)
    avg_completion_days = db.Column(db.Float, default=0.0)
    on_time_rate = db.Column(db.Float, default=0.0)
    rating_updated_at = db.Column(db.DateTime)
    achievements = db.Column(db.Text)
    best_month = db.Column(db.String(7))
    best_month_count = db.Column(db.Integer, default=0)

    user = db.relationship('User', backref='employee')
    department = db.relationship('Department', backref='employees')

    def __repr__(self):
        return f'<Employee {self.user.full_name} - {self.department.name}>'


class Resolution(db.Model):
    """Резолюция (поручение) от главы/ответственного"""
    __tablename__ = 'resolutions'

    id = db.Column(db.Integer, primary_key=True)
    appeal_id = db.Column(db.Integer, db.ForeignKey('appeals.id', ondelete='CASCADE'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    executor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    text = db.Column(db.Text, nullable=False)
    deadline_days = db.Column(db.Integer, default=30)
    deadline_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime)

    appeal = db.relationship('Appeal', backref='resolutions')
    author = db.relationship('User', foreign_keys=[author_id])
    executor = db.relationship('User', foreign_keys=[executor_id])
    department = db.relationship('Department')

    def __repr__(self):
        return f'<Resolution {self.id} for Appeal {self.appeal_id}>'


class AppealHistory(db.Model):
    """История движения обращения"""
    __tablename__ = 'appeal_history'

    id = db.Column(db.Integer, primary_key=True)
    appeal_id = db.Column(db.Integer, db.ForeignKey('appeals.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)

    appeal = db.relationship('Appeal', backref='history')
    user = db.relationship('User')

    def __repr__(self):
        return f'<AppealHistory {self.action} on Appeal {self.appeal_id}>'


class Notification(db.Model):
    """Уведомления"""
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    appeal_id = db.Column(db.Integer, db.ForeignKey('appeals.id', ondelete='CASCADE'))
    title = db.Column(db.String(200))
    message = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    user = db.relationship('User')
    appeal = db.relationship('Appeal')

    def __repr__(self):
        return f'<Notification {self.title}>'


class PasswordResetToken(db.Model):
    """Токены для сброса пароля"""
    __tablename__ = 'password_reset_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    user = db.relationship('User', backref='reset_tokens')

    def is_valid(self):
        return not self.is_used and self.expires_at > datetime.now()

    def __repr__(self):
        return f'<PasswordResetToken for User {self.user_id}>'


class AppealFile(db.Model):
    """Прикрепленные файлы к обращениям"""
    __tablename__ = 'appeal_files'

    id = db.Column(db.Integer, primary_key=True)
    appeal_id = db.Column(db.Integer, db.ForeignKey('appeals.id', ondelete='CASCADE'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(100))
    file_path = db.Column(db.String(500))
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.now)

    appeal = db.relationship('Appeal', backref='files')
    user = db.relationship('User')

    def __repr__(self):
        return f'<AppealFile {self.original_filename}>'


class AuditLog(db.Model):
    """Лог всех действий в системе"""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(80))
    user_role = db.Column(db.String(20))
    user_ip = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    action = db.Column(db.String(100), nullable=False)
    action_type = db.Column(db.String(20))
    target_type = db.Column(db.String(50))
    target_id = db.Column(db.Integer)
    target_name = db.Column(db.String(200))
    details = db.Column(db.Text)
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    status = db.Column(db.String(20), default='success')
    error_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    session_id = db.Column(db.String(100))

    user = db.relationship('User', foreign_keys=[user_id])

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.username}>'


class LoginAttempt(db.Model):
    """Лог попыток входа"""
    __tablename__ = 'login_attempts'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    success = db.Column(db.Boolean, default=False)
    failure_reason = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f'<LoginAttempt {self.username} {"success" if self.success else "failed"}>'


class DailyStats(db.Model):
    """Ежедневная статистика для мониторинга"""
    __tablename__ = 'daily_stats'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, unique=True)
    unique_users = db.Column(db.Integer, default=0)
    total_logins = db.Column(db.Integer, default=0)
    failed_logins = db.Column(db.Integer, default=0)
    new_appeals = db.Column(db.Integer, default=0)
    closed_appeals = db.Column(db.Integer, default=0)
    edited_appeals = db.Column(db.Integer, default=0)
    deleted_appeals = db.Column(db.Integer, default=0)
    exports_count = db.Column(db.Integer, default=0)
    api_calls = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def __repr__(self):
        return f'<DailyStats {self.date}>'


class RatingHistory(db.Model):
    """История изменения рейтинга"""
    __tablename__ = 'rating_history'

    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    rating_score = db.Column(db.Float)
    completed_count = db.Column(db.Integer)
    overdue_count = db.Column(db.Integer)
    avg_completion_days = db.Column(db.Float)
    on_time_rate = db.Column(db.Float)
    calculation_date = db.Column(db.Date, default=datetime.now().date)
    created_at = db.Column(db.DateTime, default=datetime.now)

    employee = db.relationship('Employee', backref='rating_history')

    def __repr__(self):
        return f'<RatingHistory for Employee {self.employee_id}>'


class DepartmentRating(db.Model):
    """Рейтинг отделов"""
    __tablename__ = 'department_ratings'

    id = db.Column(db.Integer, primary_key=True)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=False)
    total_completed = db.Column(db.Integer, default=0)
    total_overdue = db.Column(db.Integer, default=0)
    avg_completion_days = db.Column(db.Float, default=0.0)
    rating_score = db.Column(db.Float, default=0.0)
    calculation_date = db.Column(db.Date, default=datetime.now().date)

    department = db.relationship('Department', backref='ratings')

    def __repr__(self):
        return f'<DepartmentRating for Department {self.department_id}>'


class ArchivedAppeal(db.Model):
    """Архив обращений"""
    __tablename__ = 'archived_appeals'

    id = db.Column(db.Integer, primary_key=True)
    original_id = db.Column(db.Integer)
    reg_number = db.Column(db.String(50))
    registration_number = db.Column(db.String(50))
    registration_date = db.Column(db.Date)
    registered_by_id = db.Column(db.Integer)
    appeal_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime)
    citizen_name = db.Column(db.String(200))
    citizen_phone = db.Column(db.String(20))
    citizen_email = db.Column(db.String(100))
    citizen_address = db.Column(db.String(300))
    is_anonymous = db.Column(db.Boolean, default=False)
    type_id = db.Column(db.Integer)
    type_name = db.Column(db.String(100))
    content = db.Column(db.Text)
    status_id = db.Column(db.Integer)
    status_name = db.Column(db.String(50))
    executor = db.Column(db.String(200))
    resolution_text = db.Column(db.Text)
    resolution_date = db.Column(db.Date)
    notes = db.Column(db.Text)
    priority = db.Column(db.Integer)
    created_by = db.Column(db.Integer)
    created_by_name = db.Column(db.String(200))
    days_to_complete = db.Column(db.Integer)
    archived_at = db.Column(db.DateTime, default=datetime.now)
    archived_by = db.Column(db.String(100))

    def __repr__(self):
        return f'<ArchivedAppeal {self.registration_number}>'


class ArchivedAppealHistory(db.Model):
    """Архив истории обращений"""
    __tablename__ = 'archived_appeal_history'

    id = db.Column(db.Integer, primary_key=True)
    appeal_id = db.Column(db.Integer)
    original_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    user_name = db.Column(db.String(200))
    action = db.Column(db.String(100))
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime)
    archived_at = db.Column(db.DateTime, default=datetime.now)


class ArchivedAppealComment(db.Model):
    """Архив комментариев"""
    __tablename__ = 'archived_appeal_comments'

    id = db.Column(db.Integer, primary_key=True)
    appeal_id = db.Column(db.Integer)
    original_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    user_name = db.Column(db.String(200))
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime)
    archived_at = db.Column(db.DateTime, default=datetime.now)


class ArchivedResolution(db.Model):
    """Архив резолюций"""
    __tablename__ = 'archived_resolutions'

    id = db.Column(db.Integer, primary_key=True)
    appeal_id = db.Column(db.Integer)
    original_id = db.Column(db.Integer)
    author_id = db.Column(db.Integer)
    author_name = db.Column(db.String(200))
    executor_id = db.Column(db.Integer)
    executor_name = db.Column(db.String(200))
    department_id = db.Column(db.Integer)
    department_name = db.Column(db.String(200))
    text = db.Column(db.Text)
    deadline_days = db.Column(db.Integer)
    deadline_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime)
    is_completed = db.Column(db.Boolean)
    completed_at = db.Column(db.DateTime)
    archived_at = db.Column(db.DateTime, default=datetime.now)


class ArchivingLog(db.Model):
    """Лог архивации"""
    __tablename__ = 'archiving_logs'

    id = db.Column(db.Integer, primary_key=True)
    operation_type = db.Column(db.String(50))
    appeal_id = db.Column(db.Integer)
    appeal_number = db.Column(db.String(50))
    appeal_data = db.Column(db.Text)
    status = db.Column(db.String(20))
    error_message = db.Column(db.Text)
    processed_by = db.Column(db.String(100))
    processed_at = db.Column(db.DateTime, default=datetime.now)
    items_count = db.Column(db.Integer)


class Appeal(db.Model):
    __tablename__ = 'appeals'

    id = db.Column(db.Integer, primary_key=True)
    reg_number = db.Column(db.String(50), unique=True)
    registration_number = db.Column(db.String(50), unique=True)
    registration_date = db.Column(db.Date)
    registered_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    appeal_date = db.Column(db.Date, default=datetime.now().date)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    citizen_name = db.Column(db.String(200), nullable=False)
    citizen_phone = db.Column(db.String(20))
    citizen_email = db.Column(db.String(100))
    citizen_address = db.Column(db.String(300))
    is_anonymous = db.Column(db.Boolean, default=False)

    type_id = db.Column(db.Integer, db.ForeignKey('appeal_types.id'))
    content = db.Column(db.Text, nullable=False)

    status_id = db.Column(db.Integer, db.ForeignKey('appeal_statuses.id'), default=1)
    executor = db.Column(db.String(200))
    resolution_text = db.Column(db.Text)
    resolution_date = db.Column(db.Date)

    notes = db.Column(db.Text)
    priority = db.Column(db.Integer, default=2)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    needs_clarification = db.Column(db.Boolean, default=False)
    clarification_text = db.Column(db.Text)

    final_response_sent = db.Column(db.Boolean, default=False)
    response_sent_date = db.Column(db.Date)
    secretary_approved = db.Column(db.Boolean, default=False)
    secretary_comment = db.Column(db.Text)
    executor_response_date = db.Column(db.Date)

    deadline_date = db.Column(db.Date)
    days_overdue = db.Column(db.Integer, default=0)
    is_overdue = db.Column(db.Boolean, default=False)
    reminder_sent_7 = db.Column(db.Boolean, default=False)
    reminder_sent_3 = db.Column(db.Boolean, default=False)
    reminder_sent_1 = db.Column(db.Boolean, default=False)
    execution_days = db.Column(db.Integer)

    type = db.relationship('AppealType', backref='appeals')
    status = db.relationship('AppealStatus', backref='appeals')
    creator = db.relationship('User', foreign_keys=[created_by])
    registered_by = db.relationship('User', foreign_keys=[registered_by_id])

    def __repr__(self):
        return f'<Appeal {self.registration_number or self.reg_number or self.id}>'