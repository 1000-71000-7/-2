from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from functools import wraps
import re
import logging
import os
import secrets
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Конфигурация
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Настройки почты
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.mail.ru')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 465))
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'True') == 'True'
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'False') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Инициализация расширений
from models import db, User, Appeal, AppealType, AppealStatus, Department, Employee, Resolution, AppealHistory, \
    AppealComment, Notification, PasswordResetToken, AuditLog, LoginAttempt, RatingHistory, DepartmentRating, \
    ArchivedAppeal
from forms import (
    LoginForm, RegistrationForm, UserProfileForm, ClientAppealForm,
    OperatorAppealForm, StatusChangeForm, CommentForm, ResolutionForm, UserForm,
    DepartmentForm, CreateEmployeeUserForm, RegisterAppealForm
)

db.init_app(app)
mail = Mail(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============ ДЕКОРАТОРЫ ============

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            flash('Сессия устарела. Пожалуйста, войдите снова.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def operator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            flash('Сессия устарела. Пожалуйста, войдите снова.', 'warning')
            return redirect(url_for('login'))
        if user.role not in ['admin', 'operator', 'secretary']:
            flash('Доступ запрещён. Требуются права оператора.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            flash('Сессия устарела. Пожалуйста, войдите снова.', 'warning')
            return redirect(url_for('login'))
        if not user.is_admin():
            flash('Доступ запрещён. Требуются права администратора.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


def secretary_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            flash('Сессия устарела. Пожалуйста, войдите снова.', 'warning')
            return redirect(url_for('login'))
        if user.role not in ['admin', 'secretary']:
            flash('Доступ запрещён. Требуются права секретаря.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


def executor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            flash('Сессия устарела. Пожалуйста, войдите снова.', 'warning')
            return redirect(url_for('login'))
        if user.role not in ['admin', 'executor']:
            flash('Доступ запрещён. Требуются права исполнителя.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


# ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============

def add_history(appeal_id, user_id, action, comment):
    try:
        history = AppealHistory(
            appeal_id=appeal_id,
            user_id=user_id,
            action=action,
            comment=comment
        )
        db.session.add(history)
        db.session.commit()
    except Exception as e:
        logger.error(f"Ошибка истории: {e}")


def log_audit(action, action_type, target_type=None, target_id=None, target_name=None, details=None, status='success'):
    try:
        log = AuditLog(
            user_id=session.get('user_id'),
            username=session.get('username', 'system'),
            user_role=session.get('role', 'system'),
            user_ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:500],
            action=action,
            action_type=action_type,
            target_type=target_type,
            target_id=target_id,
            target_name=target_name,
            details=details,
            status=status
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Ошибка аудита: {e}")


# ============ ФУНКЦИИ ДЛЯ ОТПРАВКИ УВЕДОМЛЕНИЙ ============

def send_email_notification(recipient_email, subject, body, html_body=None):
    print(f"=== ОТПРАВКА ПИСЬМА ===")
    print(f"Кому: {recipient_email}")
    print(f"Тема: {subject}")
    print(f"MAIL_USERNAME: {app.config.get('MAIL_USERNAME')}")
    print(f"MAIL_SERVER: {app.config.get('MAIL_SERVER')}")
    print(f"MAIL_PORT: {app.config.get('MAIL_PORT')}")
    print(f"MAIL_USE_TLS: {app.config.get('MAIL_USE_TLS')}")
    print(f"MAIL_USE_SSL: {app.config.get('MAIL_USE_SSL')}")
    print(f"MAIL_DEFAULT_SENDER: {app.config.get('MAIL_DEFAULT_SENDER')}")

    if not recipient_email:
        print("❌ Email получателя не указан!")
        return False

    try:
        sender = app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')

        msg = Message(
            subject=subject,
            sender=sender,
            recipients=[recipient_email],
            body=body,
            html=html_body
        )
        mail.send(msg)
        print("✅ Письмо отправлено успешно!")
        return True
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        logger.error(f"Ошибка email: {e}")
        return False


def send_new_assignment_notification(executor_email, executor_name, appeal, resolution, deadline_days):
    subject = f"Новое поручение по обращению #{appeal.registration_number}"
    body = f"""
Уважаемый(ая) {executor_name}!

Вам назначено новое поручение по обращению гражданина.

Регистрационный номер: {appeal.registration_number}
Заявитель: {appeal.citizen_name}
Содержание: {appeal.content[:200]}

Резолюция: {resolution.text}
Срок исполнения: {deadline_days} дней

Войдите в систему: {url_for('executor_appeals_list', _external=True)}
"""
    return send_email_notification(executor_email, subject, body)


def send_status_update_notification(recipient_email, recipient_name, appeal, new_status, comment=""):
    subject = f"Изменение статуса обращения #{appeal.reg_number or appeal.id}"
    body = f"""
Уважаемый(ая) {recipient_name}!

Статус вашего обращения изменился.

Обращение №{appeal.reg_number or appeal.id}
Новый статус: {new_status}
{comment}

Следить за обращением: {url_for('client_view_appeal', id=appeal.id, _external=True)}
"""
    return send_email_notification(recipient_email, subject, body)


def send_response_notification(recipient_email, recipient_name, appeal):
    subject = f"Ответ на ваше обращение #{appeal.registration_number}"
    body = f"""
Уважаемый(ая) {recipient_name}!

По вашему обращению №{appeal.registration_number} подготовлен ответ.

Ответ: {appeal.resolution_text}

Просмотреть: {url_for('client_view_appeal', id=appeal.id, _external=True)}
"""
    return send_email_notification(recipient_email, subject, body)


def send_deadline_reminder(executor_email, executor_name, appeal, days_left):
    subject = f"Напоминание: приближается срок по обращению #{appeal.registration_number}"
    body = f"""
Уважаемый(ая) {executor_name}!

Срок исполнения поручения по обращению №{appeal.registration_number}
истекает через {days_left} дней.

Ссылка: {url_for('executor_prepare_response', id=appeal.id, _external=True)}
"""
    return send_email_notification(executor_email, subject, body)


# ============ ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ ============

def init_database():
    with app.app_context():
        try:
            db.create_all()

            if AppealType.query.count() == 0:
                types = [
                    AppealType(name='Вопрос', sort_order=1),
                    AppealType(name='Жалоба', sort_order=2),
                    AppealType(name='Предложение', sort_order=3),
                    AppealType(name='Заявление', sort_order=4)
                ]
                db.session.add_all(types)

            if AppealStatus.query.count() == 0:
                statuses = [
                    AppealStatus(name='Новое (на регистрации)', is_final=False, sort_order=1),
                    AppealStatus(name='Зарегистрировано', is_final=False, sort_order=2),
                    AppealStatus(name='На рассмотрении', is_final=False, sort_order=3),
                    AppealStatus(name='Назначен исполнитель', is_final=False, sort_order=4),
                    AppealStatus(name='Ответ подготовлен', is_final=False, sort_order=5),
                    AppealStatus(name='Одобрено', is_final=False, sort_order=6),
                    AppealStatus(name='На доработке', is_final=False, sort_order=7),
                    AppealStatus(name='Ответ отправлен', is_final=True, sort_order=8),
                    AppealStatus(name='Отклонено', is_final=True, sort_order=9)
                ]
                db.session.add_all(statuses)

            if Department.query.count() == 0:
                departments = [
                    Department(name='Отдел ЖКХ', sort_order=1),
                    Department(name='Отдел дорожного хозяйства', sort_order=2),
                    Department(name='Отдел социальной защиты', sort_order=3),
                    Department(name='Земельный отдел', sort_order=4),
                    Department(name='Общий отдел', sort_order=5)
                ]
                db.session.add_all(departments)

            if User.query.count() == 0:
                admin = User(username='admin', role='admin', full_name='Администратор', is_active=True)
                admin.set_password('admin123')
                secretary = User(username='secretary', role='secretary', full_name='Секретарь', is_active=True)
                secretary.set_password('secretary123')
                executor = User(username='executor', role='executor', full_name='Исполнитель', is_active=True)
                executor.set_password('executor123')
                operator = User(username='operator', role='operator', full_name='Оператор', is_active=True)
                operator.set_password('operator123')
                client = User(username='client', role='client', full_name='Тестовый Клиент', email='client@example.com',
                              is_active=True)
                client.set_password('client123')
                db.session.add_all([admin, secretary, executor, operator, client])

            db.session.commit()
            logger.info("База данных инициализирована")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Ошибка инициализации: {e}")


init_database()


# ============ ПУБЛИЧНЫЕ МАРШРУТЫ ============

@app.route('/')
def index():
    return render_template('public_index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.role == 'client':
            return redirect(url_for('dashboard'))
        return redirect(url_for('operator_dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            if User.query.filter_by(username=form.username.data).first():
                flash('Логин уже существует', 'danger')
                return render_template('register.html', form=form)
            if form.email.data and User.query.filter_by(email=form.email.data).first():
                flash('Email уже существует', 'danger')
                return render_template('register.html', form=form)

            user = User(
                username=form.username.data,
                role='client',
                full_name=form.full_name.data,
                email=form.email.data,
                phone=form.phone.data,
                is_active=True
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Регистрация успешна!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при регистрации', 'danger')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            if user.role == 'client':
                return redirect(url_for('dashboard'))
            return redirect(url_for('operator_dashboard'))
        session.clear()

    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter(
                (User.username == form.username.data) |
                (User.email == form.username.data)
            ).first()

            if user and user.check_password(form.password.data):
                if not user.is_active:
                    flash('Аккаунт заблокирован', 'danger')
                    return render_template('login.html', form=form)

                session.clear()
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role
                session['full_name'] = user.full_name
                session['email'] = user.email
                user.update_last_login()
                db.session.commit()
                log_audit('login', 'auth', target_name=user.username, details="Успешный вход")
                flash(f'Добро пожаловать, {user.full_name}!', 'success')

                if user.role == 'client':
                    return redirect(url_for('dashboard'))
                return redirect(url_for('operator_dashboard'))
            else:
                flash('Неверный логин или пароль', 'danger')
        except Exception as e:
            flash('Ошибка при входе', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit('logout', 'auth', target_name=session.get('username'), details="Выход из системы")
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(32)
            reset_token = PasswordResetToken(
                user_id=user.id,
                token=token,
                expires_at=datetime.now() + timedelta(hours=24)
            )
            db.session.add(reset_token)
            db.session.commit()
            reset_url = url_for('reset_password', token=token, _external=True)
            try:
                msg = Message('Восстановление пароля', recipients=[user.email],
                              body=f"Ссылка для сброса пароля: {reset_url}")
                mail.send(msg)
                flash('Инструкция отправлена на email', 'success')
            except Exception as e:
                flash('Ошибка отправки письма', 'danger')
        else:
            flash('Если аккаунт существует, инструкция будет отправлена', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token, is_used=False).first()
    if not reset_token or not reset_token.is_valid():
        flash('Ссылка недействительна или истекла', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        if password != confirm:
            flash('Пароли не совпадают', 'danger')
        elif len(password) < 6:
            flash('Пароль должен содержать минимум 6 символов', 'danger')
        else:
            user = reset_token.user
            user.set_password(password)
            reset_token.is_used = True
            db.session.commit()
            flash('Пароль успешно изменен!', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)


# ============ КЛИЕНТСКИЕ МАРШРУТЫ ============

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    if user.role != 'client':
        return redirect(url_for('operator_dashboard'))
    my_appeals = Appeal.query.filter_by(created_by=user.id).order_by(Appeal.created_at.desc()).all()
    return render_template('client_dashboard.html', user=user, my_appeals=my_appeals)


@app.route('/client/appeal/add', methods=['GET', 'POST'])
@login_required
def client_add_appeal():
    user = User.query.get(session['user_id'])
    if user.role != 'client':
        return redirect(url_for('operator_dashboard'))

    form = ClientAppealForm()
    form.type_id.choices = [(t.id, t.name) for t in AppealType.query.order_by(AppealType.sort_order).all()]

    if form.validate_on_submit():
        try:
            last_id = Appeal.query.count() + 1
            temp_number = f"ВР-{datetime.now().year}-{str(last_id).zfill(5)}"
            appeal = Appeal(
                reg_number=temp_number,
                citizen_name=user.full_name,
                citizen_phone=form.citizen_phone.data,
                citizen_email=user.email,
                citizen_address=form.citizen_address.data,
                type_id=form.type_id.data,
                content=form.content.data,
                status_id=1,
                notes=form.notes.data,
                created_by=user.id
            )
            db.session.add(appeal)
            db.session.commit()
            log_audit('create', 'appeal', 'appeal', appeal.id, temp_number, "Создано обращение")
            flash(f'Обращение #{temp_number} создано!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при сохранении', 'danger')
    return render_template('client_add_appeal.html', form=form, user=user)


@app.route('/client/appeal/<int:id>')
@login_required
def client_view_appeal(id):
    user = User.query.get(session['user_id'])
    appeal = Appeal.query.get_or_404(id)
    if appeal.created_by != user.id and user.role == 'client':
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('dashboard'))
    comments = AppealComment.query.filter_by(appeal_id=id).order_by(AppealComment.created_at).all()
    return render_template('client_view_appeal.html', appeal=appeal, comments=comments)


# ============ ОПЕРАТОРСКИЕ МАРШРУТЫ ============

@app.route('/operator')
@operator_required
def operator_dashboard():
    stats = {
        'total': Appeal.query.count(),
        'new': Appeal.query.filter_by(status_id=1).count(),
        'registered': Appeal.query.filter_by(status_id=2).count(),
        'assigned': Appeal.query.filter_by(status_id=4).count(),
        'completed': Appeal.query.filter_by(status_id=8).count()
    }
    recent_appeals = Appeal.query.order_by(Appeal.created_at.desc()).limit(10).all()
    return render_template('operator_dashboard.html', stats=stats, recent_appeals=recent_appeals)


@app.route('/operator/appeals')
@operator_required
def operator_appeals_list():
    search = request.args.get('search', '')
    status_id = request.args.get('status_id', 0, type=int)
    page = request.args.get('page', 1, type=int)
    per_page = 20

    query = Appeal.query
    if search:
        query = query.filter(Appeal.citizen_name.contains(search))
    if status_id:
        query = query.filter(Appeal.status_id == status_id)

    pagination = query.order_by(Appeal.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    statuses = AppealStatus.query.all()

    return render_template('operator_appeals_list.html',
                           appeals=pagination.items,
                           pagination=pagination,
                           statuses=statuses,
                           search=search,
                           status_id=status_id)


@app.route('/operator/appeal/<int:id>')
@operator_required
def operator_view_appeal(id):
    appeal = Appeal.query.get_or_404(id)
    comments = AppealComment.query.filter_by(appeal_id=id).order_by(AppealComment.created_at).all()
    status_form = StatusChangeForm()
    status_form.status_id.choices = [(s.id, s.name) for s in AppealStatus.query.all()]
    comment_form = CommentForm()
    return render_template('operator_view_appeal.html',
                           appeal=appeal,
                           comments=comments,
                           status_form=status_form,
                           comment_form=comment_form)


@app.route('/operator/appeal/<int:id>/change-status', methods=['POST'])
@operator_required
def operator_change_status(id):
    appeal = Appeal.query.get_or_404(id)
    form = StatusChangeForm()
    form.status_id.choices = [(s.id, s.name) for s in AppealStatus.query.all()]

    if form.validate_on_submit():
        try:
            old_status = appeal.status.name if appeal.status else 'Unknown'
            new_status = AppealStatus.query.get(form.status_id.data)
            appeal.status_id = form.status_id.data
            if form.resolution_text.data:
                appeal.resolution_text = form.resolution_text.data
            db.session.commit()

            add_history(appeal.id, session['user_id'], 'status_change', f"Статус изменен на {new_status.name}")
            log_audit('status_change', 'appeal', 'appeal', appeal.id, appeal.registration_number,
                      f"Статус: {old_status} -> {new_status.name}")

            client = User.query.get(appeal.created_by)
            if client and client.email and new_status:
                send_status_update_notification(
                    recipient_email=client.email,
                    recipient_name=client.full_name,
                    appeal=appeal,
                    new_status=new_status.name,
                    comment=form.resolution_text.data or ""
                )

            flash(f'Статус изменен на "{new_status.name}"', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при изменении статуса', 'danger')
    return redirect(url_for('operator_view_appeal', id=appeal.id))


@app.route('/operator/appeal/<int:id>/add-comment', methods=['POST'])
@operator_required
def operator_add_comment(id):
    appeal = Appeal.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        try:
            comment = AppealComment(
                appeal_id=appeal.id,
                user_id=session['user_id'],
                comment=form.comment.data.strip()
            )
            db.session.add(comment)
            db.session.commit()
            flash('Комментарий добавлен', 'success')
        except Exception as e:
            flash('Ошибка при добавлении комментария', 'danger')
    return redirect(url_for('operator_view_appeal', id=appeal.id))


@app.route('/operator/appeal/add', methods=['GET', 'POST'])
@operator_required
def operator_add_appeal():
    form = OperatorAppealForm()
    form.type_id.choices = [(t.id, t.name) for t in AppealType.query.order_by(AppealType.sort_order).all()]

    if form.validate_on_submit():
        try:
            last_id = Appeal.query.count() + 1
            temp_number = f"ВР-{datetime.now().year}-{str(last_id).zfill(5)}"
            appeal = Appeal(
                reg_number=temp_number,
                citizen_name=form.citizen_name.data.strip(),
                citizen_phone=re.sub(r'\D', '', form.citizen_phone.data) if form.citizen_phone.data else None,
                citizen_email=form.citizen_email.data,
                citizen_address=form.citizen_address.data,
                type_id=form.type_id.data,
                content=form.content.data,
                status_id=1,
                notes=form.notes.data,
                created_by=session['user_id']
            )
            db.session.add(appeal)
            db.session.commit()
            log_audit('create', 'appeal', 'appeal', appeal.id, temp_number, "Создано обращение оператором")
            flash(f'Обращение #{temp_number} создано!', 'success')
            return redirect(url_for('operator_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при создании', 'danger')
    return render_template('operator_add_appeal.html', form=form)


@app.route('/operator/appeal/<int:id>/delete', methods=['POST'])
@admin_required
def operator_delete_appeal(id):
    """Удаление обращения (только для администратора)"""
    try:
        appeal = Appeal.query.get_or_404(id)
        appeal_number = appeal.registration_number or appeal.reg_number or str(appeal.id)

        db.session.delete(appeal)
        db.session.commit()

        log_audit('delete', 'appeal', 'appeal', id, appeal_number, f"Обращение #{appeal_number} удалено")
        flash(f'Обращение #{appeal_number} успешно удалено!', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Ошибка удаления обращения: {e}")
        flash('Ошибка при удалении обращения', 'danger')

    return redirect(url_for('operator_appeals_list'))


@app.route('/operator/appeal/<int:id>/register', methods=['GET', 'POST'])
@operator_required
def operator_register_appeal(id):
    appeal = Appeal.query.get_or_404(id)
    form = RegisterAppealForm()

    employees = Employee.query.filter_by(is_available=True).all()
    form.assigned_to.choices = [(0, '-- Выберите исполнителя --')] + [
        (e.user_id, f"{e.user.full_name} - {e.position} ({e.department.name})")
        for e in employees
    ]

    if form.validate_on_submit():
        try:
            existing = Appeal.query.filter_by(registration_number=form.reg_number.data).first()
            if existing and existing.id != appeal.id:
                flash('Обращение с таким номером уже существует', 'danger')
                return render_template('operator_register_appeal.html', form=form, appeal=appeal)

            appeal.registration_number = form.reg_number.data
            appeal.registration_date = datetime.now().date()
            appeal.registered_by_id = session['user_id']
            appeal.status_id = 2
            db.session.commit()

            if form.resolution_text.data and form.assigned_to.data != 0:
                deadline_days = form.deadline_days.data
                deadline_date = datetime.now().date() + timedelta(days=deadline_days)

                resolution = Resolution(
                    appeal_id=appeal.id,
                    author_id=session['user_id'],
                    executor_id=form.assigned_to.data,
                    text=form.resolution_text.data,
                    deadline_days=deadline_days,
                    deadline_date=deadline_date
                )
                db.session.add(resolution)

                appeal.status_id = 4
                executor = User.query.get(form.assigned_to.data)
                appeal.executor = executor.full_name if executor else None
                appeal.deadline_date = deadline_date

                db.session.commit()

                if request.form.get('notify_executor') and executor and executor.email:
                    send_new_assignment_notification(
                        executor_email=executor.email,
                        executor_name=executor.full_name,
                        appeal=appeal,
                        resolution=resolution,
                        deadline_days=deadline_days
                    )
                    flash(f'Уведомление отправлено исполнителю {executor.full_name}', 'info')

                add_history(appeal.id, session['user_id'], 'resolution',
                            f'Назначен исполнитель: {appeal.executor}. Срок: {deadline_days} дней')

            add_history(appeal.id, session['user_id'], 'registration',
                        f'Обращение зарегистрировано за №{appeal.registration_number}')

            flash(f'Обращение зарегистрировано за №{appeal.registration_number}', 'success')
            return redirect(url_for('operator_appeals_list'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Ошибка регистрации: {e}")
            flash('Ошибка при регистрации', 'danger')

    if not form.reg_number.data:
        year = datetime.now().year
        existing_numbers = Appeal.query.filter(
            Appeal.registration_number.like(f'{year}-%')
        ).count()
        count = existing_numbers + 1
        form.reg_number.data = f"{year}-{str(count).zfill(5)}"

    return render_template('operator_register_appeal.html', form=form, appeal=appeal)


# ============ СЕКРЕТАРСКИЕ МАРШРУТЫ ============

@app.route('/secretary/appeals')
@secretary_required
def secretary_appeals_list():
    search = request.args.get('search', '')
    status_id = request.args.get('status_id', 1, type=int)
    query = Appeal.query.filter(Appeal.registration_number.is_(None))
    if search:
        query = query.filter(Appeal.citizen_name.contains(search))
    if status_id:
        query = query.filter(Appeal.status_id == status_id)
    appeals = query.order_by(Appeal.created_at.asc()).all()
    statuses = AppealStatus.query.all()
    return render_template('secretary_appeals_list.html', appeals=appeals, statuses=statuses, search=search,
                           status_id=status_id)


@app.route('/secretary/appeal/<int:id>/register', methods=['GET', 'POST'])
@secretary_required
def secretary_register_appeal(id):
    appeal = Appeal.query.get_or_404(id)
    if request.method == 'POST':
        try:
            year = datetime.now().year
            last_num = Appeal.query.filter(Appeal.registration_number.like(f'{year}-%')).count() + 1
            appeal.registration_number = f"{year}-{str(last_num).zfill(5)}"
            appeal.registration_date = datetime.now().date()
            appeal.registered_by_id = session['user_id']
            appeal.status_id = 2
            db.session.commit()
            add_history(appeal.id, session['user_id'], 'registration',
                        f'Зарегистрировано за №{appeal.registration_number}')
            flash(f'Обращение зарегистрировано за №{appeal.registration_number}', 'success')
            return redirect(url_for('secretary_appeals_list'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при регистрации', 'danger')
    return render_template('secretary_register_appeal.html', appeal=appeal)


@app.route('/secretary/appeal/<int:id>/send-response', methods=['POST'])
@secretary_required
def secretary_send_response(id):
    appeal = Appeal.query.get_or_404(id)
    try:
        appeal.final_response_sent = True
        appeal.response_sent_date = datetime.now().date()
        appeal.status_id = 8
        db.session.commit()

        add_history(appeal.id, session['user_id'], 'send_response', 'Ответ отправлен заявителю')

        client = User.query.get(appeal.created_by)
        if client and client.email:
            send_response_notification(
                recipient_email=client.email,
                recipient_name=client.full_name,
                appeal=appeal
            )
            flash('Ответ отправлен заявителю на email', 'success')
        else:
            flash('У заявителя не указан email', 'warning')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при отправке', 'danger')
    return redirect(url_for('secretary_appeals_list'))


# ============ РУКОВОДИТЕЛЬ / ГЛАВА ============

@app.route('/head/appeal/<int:id>/resolution', methods=['GET', 'POST'])
@admin_required
def head_add_resolution(id):
    appeal = Appeal.query.get_or_404(id)
    form = ResolutionForm()
    employees = Employee.query.filter_by(is_available=True).all()
    form.executor_id.choices = [(0, '-- Выберите исполнителя --')] + [
        (e.user_id, f"{e.user.full_name} ({e.department.name})") for e in employees]
    form.department_id.choices = [(0, 'Все отделы')] + [(d.id, d.name) for d in Department.query.all()]

    if form.validate_on_submit():
        try:
            deadline_date = form.deadline_date.data or (datetime.now().date() + timedelta(days=form.deadline_days.data))
            resolution = Resolution(
                appeal_id=appeal.id,
                author_id=session['user_id'],
                executor_id=form.executor_id.data if form.executor_id.data != 0 else None,
                text=form.text.data,
                deadline_days=form.deadline_days.data,
                deadline_date=deadline_date
            )
            db.session.add(resolution)
            appeal.status_id = 4
            appeal.deadline_date = deadline_date
            executor = None
            if form.executor_id.data != 0:
                executor = User.query.get(form.executor_id.data)
                appeal.executor = executor.full_name
            db.session.commit()

            add_history(appeal.id, session['user_id'], 'resolution', f'Назначен исполнитель: {appeal.executor}')

            if form.executor_id.data != 0 and executor and executor.email:
                send_new_assignment_notification(
                    executor_email=executor.email,
                    executor_name=executor.full_name,
                    appeal=appeal,
                    resolution=resolution,
                    deadline_days=form.deadline_days.data
                )
                flash('Уведомление отправлено исполнителю', 'info')

            flash('Резолюция наложена, исполнитель назначен', 'success')
            return redirect(url_for('operator_appeals_list'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при сохранении резолюции', 'danger')

    if not form.deadline_date.data:
        form.deadline_date.data = datetime.now().date() + timedelta(days=30)
    return render_template('head_add_resolution.html', form=form, appeal=appeal)


# ============ ИСПОЛНИТЕЛЬ ============

@app.route('/executor/appeals')
@executor_required
def executor_appeals_list():
    resolutions = Resolution.query.filter_by(executor_id=session['user_id']).all()
    appeal_ids = [r.appeal_id for r in resolutions]
    appeals = Appeal.query.filter(Appeal.id.in_(appeal_ids)).order_by(Appeal.registration_date.desc()).all()
    return render_template('executor_appeals_list.html', appeals=appeals)


@app.route('/executor/appeal/<int:id>/respond', methods=['GET', 'POST'])
@executor_required
def executor_prepare_response(id):
    appeal = Appeal.query.get_or_404(id)
    if request.method == 'POST':
        try:
            appeal.resolution_text = request.form.get('response_text')
            appeal.status_id = 5
            appeal.executor_response_date = datetime.now().date()
            db.session.commit()
            add_history(appeal.id, session['user_id'], 'prepare_response', 'Ответ подготовлен')
            flash('Ответ подготовлен и отправлен на проверку', 'success')
            return redirect(url_for('executor_appeals_list'))
        except Exception as e:
            flash('Ошибка при сохранении ответа', 'danger')
    return render_template('executor_prepare_response.html', appeal=appeal)


# ============ СТАТИСТИКА ============

@app.route('/statistics')
@operator_required
def statistics():
    status_stats = [{'name': s.name, 'count': Appeal.query.filter_by(status_id=s.id).count()} for s in
                    AppealStatus.query.order_by(AppealStatus.sort_order).all()]
    type_stats = [{'name': t.name, 'count': Appeal.query.filter_by(type_id=t.id).count()} for t in
                  AppealType.query.order_by(AppealType.sort_order).all()]

    from sqlalchemy import func
    monthly_data = db.session.query(func.strftime('%Y-%m', Appeal.appeal_date).label('month'),
                                    func.count(Appeal.id).label('count')).group_by('month').order_by('month').all()
    monthly_stats = [{'month': m[0], 'count': m[1]} for m in monthly_data]

    return render_template('statistics.html', status_stats=status_stats, type_stats=type_stats,
                           monthly_stats=monthly_stats)


# ============ ПРОФИЛЬ ============

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    form = UserProfileForm()
    if form.validate_on_submit():
        try:
            user.full_name = form.full_name.data
            user.email = form.email.data
            user.phone = form.phone.data
            if form.new_password.data:
                if user.check_password(form.current_password.data):
                    user.set_password(form.new_password.data)
                    flash('Пароль изменен!', 'success')
                else:
                    flash('Неверный текущий пароль', 'danger')
                    return render_template('profile.html', form=form, user=user)
            db.session.commit()
            session['full_name'] = user.full_name
            flash('Профиль обновлен!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при обновлении', 'danger')

    form.full_name.data = user.full_name
    form.email.data = user.email
    form.phone.data = user.phone
    return render_template('profile.html', form=form, user=user)


# ============ АДМИНИСТРИРОВАНИЕ ============

@app.route('/users')
@admin_required
def users_list():
    users = User.query.all()
    return render_template('users.html', users=users)


@app.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    form = UserForm()
    if form.validate_on_submit():
        try:
            if User.query.filter_by(username=form.username.data).first():
                flash('Логин уже существует', 'danger')
            else:
                user = User(
                    username=form.username.data,
                    role=form.role.data,
                    full_name=form.full_name.data,
                    email=form.email.data,
                    phone=form.phone.data,
                    notes=form.notes.data,
                    is_active=form.is_active.data
                )
                user.set_password(form.password.data if form.password.data else '123456')
                db.session.add(user)
                db.session.commit()
                flash('Пользователь создан!', 'success')
                return redirect(url_for('users_list'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при создании', 'danger')
    return render_template('users.html', form=form, title='Добавление пользователя')


@app.route('/users/<int:id>/delete', methods=['POST'])
@admin_required
def delete_user(id):
    if id == session['user_id']:
        flash('Нельзя удалить себя', 'danger')
        return redirect(url_for('users_list'))
    try:
        user = User.query.get_or_404(id)
        db.session.delete(user)
        db.session.commit()
        flash('Пользователь удален', 'warning')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при удалении', 'danger')
    return redirect(url_for('users_list'))


# ============ УПРАВЛЕНИЕ ОТДЕЛАМИ ============

@app.route('/departments')
@admin_required
def departments_list():
    departments = Department.query.order_by(Department.sort_order).all()
    return render_template('departments_list.html', departments=departments)


@app.route('/departments/add', methods=['GET', 'POST'])
@admin_required
def department_add():
    form = DepartmentForm()
    if form.validate_on_submit():
        try:
            department = Department(
                name=form.name.data,
                description=form.description.data,
                head_name=form.head_name.data,
                email=form.email.data,
                phone=form.phone.data,
                sort_order=form.sort_order.data
            )
            db.session.add(department)
            db.session.commit()
            flash(f'Отдел "{form.name.data}" создан', 'success')
            return redirect(url_for('departments_list'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при создании отдела', 'danger')
    return render_template('department_form.html', form=form, title='Добавить отдел')


@app.route('/departments/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def department_edit(id):
    department = Department.query.get_or_404(id)
    form = DepartmentForm(obj=department)

    if form.validate_on_submit():
        try:
            department.name = form.name.data
            department.description = form.description.data
            department.head_name = form.head_name.data
            department.email = form.email.data
            department.phone = form.phone.data
            department.sort_order = form.sort_order.data
            db.session.commit()
            flash('Отдел обновлен', 'success')
            return redirect(url_for('departments_list'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при обновлении', 'danger')

    return render_template('department_form.html', form=form, title='Редактировать отдел', department=department)


@app.route('/departments/<int:id>/delete', methods=['POST'])
@admin_required
def department_delete(id):
    department = Department.query.get_or_404(id)
    if department.employees:
        flash('Нельзя удалить отдел, в котором есть сотрудники', 'danger')
    else:
        db.session.delete(department)
        db.session.commit()
        flash('Отдел удален', 'success')
    return redirect(url_for('departments_list'))


# ============ УПРАВЛЕНИЕ СОТРУДНИКАМИ ============

@app.route('/employees')
@admin_required
def employees_list():
    employees = Employee.query.all()
    return render_template('employees_list.html', employees=employees)


@app.route('/employees/create', methods=['GET', 'POST'])
@admin_required
def employee_create():
    form = CreateEmployeeUserForm()
    departments = Department.query.order_by(Department.sort_order).all()
    form.department_id.choices = [(d.id, d.name) for d in departments]

    if form.validate_on_submit():
        try:
            if User.query.filter_by(username=form.username.data).first():
                flash('Логин уже существует', 'danger')
                return render_template('employee_create.html', form=form)

            if form.email.data and User.query.filter_by(email=form.email.data).first():
                flash('Email уже существует', 'danger')
                return render_template('employee_create.html', form=form)

            user = User(
                username=form.username.data,
                role='executor',
                full_name=form.full_name.data,
                email=form.email.data,
                phone=form.phone.data,
                is_active=True
            )
            if form.password.data:
                user.set_password(form.password.data)
            else:
                user.set_password('123456')
                flash('Пароль по умолчанию: 123456', 'info')

            db.session.add(user)
            db.session.flush()

            employee = Employee(
                user_id=user.id,
                department_id=form.department_id.data,
                position=form.position.data,
                phone_work=form.phone_work.data,
                is_available=True
            )
            db.session.add(employee)
            db.session.commit()

            flash(f'Сотрудник {form.full_name.data} создан!', 'success')
            return redirect(url_for('employees_list'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Ошибка создания сотрудника: {e}")
            flash('Ошибка при создании сотрудника', 'danger')

    return render_template('employee_create.html', form=form)


@app.route('/employees/<int:id>/toggle', methods=['POST'])
@admin_required
def employee_toggle(id):
    employee = Employee.query.get_or_404(id)
    employee.is_available = not employee.is_available
    db.session.commit()
    status = 'активен' if employee.is_available else 'неактивен'
    flash(f'Сотрудник {employee.user.full_name} теперь {status}', 'info')
    return redirect(url_for('employees_list'))


@app.route('/employees/<int:id>/delete', methods=['POST'])
@admin_required
def employee_delete(id):
    employee = Employee.query.get_or_404(id)
    name = employee.user.full_name

    has_active = Resolution.query.filter_by(executor_id=employee.user_id, is_completed=False).first()

    if has_active:
        flash('Нельзя удалить сотрудника с активными поручениями', 'danger')
    else:
        db.session.delete(employee.user)
        db.session.commit()
        flash(f'Сотрудник {name} удален', 'success')

    return redirect(url_for('employees_list'))


# ============ РЕЙТИНГ ============

@app.route('/rating')
@admin_required
def rating_dashboard():
    top_employees = Employee.query.filter(Employee.completed_count > 0).order_by(Employee.rating_score.desc()).limit(
        10).all()
    return render_template('rating_dashboard.html', top_employees=top_employees)


# ============ АУДИТ ============

@app.route('/audit')
@admin_required
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return render_template('audit_logs.html', logs=logs)


# ============ АРХИВ ============

@app.route('/archive')
@admin_required
def archive_list():
    archived = ArchivedAppeal.query.order_by(ArchivedAppeal.archived_at.desc()).limit(100).all()
    return render_template('archive_list.html', archived_appeals=archived)


# ============ ПУБЛИЧНЫЕ ОТВЕТЫ ============

@app.route('/public-appeals')
def public_appeals():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    pagination = Appeal.query.filter(
        Appeal.status_id == 8,
        Appeal.resolution_text.isnot(None),
        Appeal.resolution_text != ''
    ).order_by(Appeal.response_sent_date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('public_appeals.html', pagination=pagination)


@app.route('/public-appeal/<int:id>')
def public_appeal_view(id):
    appeal = Appeal.query.get_or_404(id)
    if appeal.status_id != 8 or not appeal.resolution_text:
        flash('Ответ на это обращение еще не опубликован', 'warning')
        return redirect(url_for('public_appeals'))
    return render_template('public_appeal_view.html', appeal=appeal)


# ============ CLI КОМАНДЫ ============

@app.cli.command("send-reminders")
def send_reminders():
    with app.app_context():
        today = datetime.now().date()
        resolutions = Resolution.query.filter_by(is_completed=False).all()
        sent = 0
        for resolution in resolutions:
            if resolution.deadline_date:
                days_left = (resolution.deadline_date - today).days
                if days_left in [7, 3, 1] and days_left > 0:
                    executor = User.query.get(resolution.executor_id)
                    if executor and executor.email:
                        send_deadline_reminder(
                            executor_email=executor.email,
                            executor_name=executor.full_name,
                            appeal=resolution.appeal,
                            days_left=days_left
                        )
                        sent += 1
        print(f"Отправлено напоминаний: {sent}")


if __name__ == '__main__':
    app.run(debug=True)