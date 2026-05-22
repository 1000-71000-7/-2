from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, IntegerField, \
    DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
import re
from datetime import datetime


# ============ ВАЛИДАТОРЫ ============

def validate_phone(form, field):
    """Валидация номера телефона"""
    if field.data:
        phone_clean = re.sub(r'\D', '', field.data)
        if len(phone_clean) < 10 or len(phone_clean) > 15:
            raise ValidationError('Введите корректный номер телефона (10-15 цифр)')


def validate_password_strength(form, field):
    """Проверка сложности пароля"""
    if field.data:
        if len(field.data) < 8:
            raise ValidationError('Пароль должен содержать минимум 8 символов')
        if not re.search(r'[A-ZА-Я]', field.data):
            raise ValidationError('Пароль должен содержать хотя бы одну заглавную букву')
        if not re.search(r'[0-9]', field.data):
            raise ValidationError('Пароль должен содержать хотя бы одну цифру')
        if not re.search(r'[a-zа-я]', field.data):
            raise ValidationError('Пароль должен содержать хотя бы одну строчную букву')


def validate_username(form, field):
    """Проверка логина на допустимые символы"""
    if not re.match(r'^[a-zA-Z0-9_]+$', field.data):
        raise ValidationError('Логин может содержать только латинские буквы, цифры и знак подчеркивания')


# ============ ФОРМЫ АВТОРИЗАЦИИ ============

class LoginForm(FlaskForm):
    """Форма входа в систему"""
    username = StringField('Логин или Email', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


class RegistrationForm(FlaskForm):
    """Форма регистрации нового пользователя"""
    username = StringField('Логин', validators=[DataRequired(), Length(min=3, max=80), validate_username])
    full_name = StringField('ФИО', validators=[DataRequired(), Length(max=200)])
    email = StringField('Email', validators=[Email(), Length(max=100)])
    phone = StringField('Телефон', validators=[Length(max=20), validate_phone])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=8), validate_password_strength])
    confirm_password = PasswordField('Подтверждение пароля', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')

    def validate_confirm_password(self, field):
        if field.data != self.password.data:
            raise ValidationError('Пароли не совпадают')


class UserProfileForm(FlaskForm):
    """Форма редактирования профиля пользователя"""
    full_name = StringField('ФИО', validators=[DataRequired(), Length(max=200)])
    email = StringField('Email', validators=[Email(), Length(max=100)])
    phone = StringField('Телефон', validators=[Length(max=20), validate_phone])
    current_password = PasswordField('Текущий пароль')
    new_password = PasswordField('Новый пароль', validators=[Length(min=8), validate_password_strength])
    confirm_password = PasswordField('Подтверждение пароля')
    submit = SubmitField('Сохранить изменения')

    def validate_confirm_password(self, field):
        if self.new_password.data and field.data != self.new_password.data:
            raise ValidationError('Пароли не совпадают')


# ============ ФОРМЫ ДЛЯ ОБРАЩЕНИЙ ============

class ClientAppealForm(FlaskForm):
    """Форма создания обращения для клиента"""
    citizen_phone = StringField('Телефон', validators=[Length(max=20), validate_phone])
    citizen_address = StringField('Адрес', validators=[Length(max=300)])
    type_id = SelectField('Тип обращения', coerce=int, validators=[DataRequired()])
    content = TextAreaField('Содержание', validators=[DataRequired(), Length(min=10, max=5000)])
    notes = TextAreaField('Примечания', validators=[Length(max=1000)])
    submit = SubmitField('Отправить обращение')


class OperatorAppealForm(FlaskForm):
    """Форма создания обращения оператором (при звонке от клиента)"""
    citizen_name = StringField('ФИО заявителя', validators=[DataRequired(), Length(max=200)])
    citizen_phone = StringField('Телефон', validators=[Length(max=20), validate_phone])
    citizen_email = StringField('Email', validators=[Email(), Length(max=100)])
    citizen_address = StringField('Адрес', validators=[Length(max=300)])
    type_id = SelectField('Тип обращения', coerce=int, validators=[DataRequired()])
    content = TextAreaField('Содержание', validators=[DataRequired(), Length(min=10, max=5000)])
    notes = TextAreaField('Примечания', validators=[Length(max=1000)])
    submit = SubmitField('Создать обращение')


class StatusChangeForm(FlaskForm):
    """Форма изменения статуса обращения"""
    status_id = SelectField('Статус', coerce=int, validators=[DataRequired()])
    resolution_text = TextAreaField('Текст решения', validators=[Length(max=2000)])
    submit = SubmitField('Изменить статус')

    def validate_resolution_text(self, field):
        from models import AppealStatus
        status = AppealStatus.query.get(self.status_id.data) if hasattr(self, 'status_id') else None
        if status and status.is_final and not field.data:
            raise ValidationError('Для финального статуса необходимо указать текст решения')


class CommentForm(FlaskForm):
    """Форма добавления комментария"""
    comment = TextAreaField('Комментарий', validators=[DataRequired(), Length(min=1, max=1000)])
    submit = SubmitField('Добавить комментарий')


class ResolutionForm(FlaskForm):
    """Форма наложения резолюции (назначения исполнителя)"""
    executor_id = SelectField('Исполнитель', coerce=int, validators=[DataRequired()])
    department_id = SelectField('Отдел (для фильтрации)', coerce=int)
    text = TextAreaField('Текст резолюции', validators=[DataRequired(), Length(min=5, max=2000)])
    deadline_days = IntegerField('Срок исполнения (дней)', default=30)
    deadline_date = DateField('Срок исполнения (дата)', validators=[DataRequired()], format='%Y-%m-%d')
    submit = SubmitField('Назначить')

    def validate_deadline_date(self, field):
        if field.data and field.data < datetime.now().date():
            raise ValidationError('Дата не может быть в прошлом')

    def validate_deadline_days(self, field):
        if field.data and field.data < 1:
            raise ValidationError('Срок должен быть не менее 1 дня')
        if field.data and field.data > 365:
            raise ValidationError('Срок не может превышать 365 дней')


class RegisterAppealForm(FlaskForm):
    """Форма для регистрации обращения + назначения исполнителя"""
    reg_number = StringField('Регистрационный номер', validators=[DataRequired(), Length(max=50)])
    resolution_text = TextAreaField('Текст резолюции / Поручение', validators=[Length(max=2000)])
    assigned_to = SelectField('Назначить исполнителя', coerce=int, validators=[DataRequired()])
    deadline_days = SelectField('Срок исполнения (дней)', coerce=int, default=30, choices=[
        (7, '7 дней (1 неделя)'),
        (14, '14 дней (2 недели)'),
        (30, '30 дней (1 месяц)'),
        (45, '45 дней (1.5 месяца)'),
        (60, '60 дней (2 месяца)'),
        (90, '90 дней (3 месяца)')
    ])
    submit = SubmitField('Зарегистрировать и назначить')

    def validate_reg_number(self, field):
        from models import Appeal
        if field.data and Appeal.query.filter_by(registration_number=field.data).first():
            raise ValidationError('Обращение с таким номером уже существует')


# ============ ФОРМЫ ДЛЯ АДМИНИСТРИРОВАНИЯ ============

class UserForm(FlaskForm):
    """Форма создания/редактирования пользователя (для администратора)"""
    username = StringField('Логин', validators=[DataRequired(), Length(min=3, max=80), validate_username])
    full_name = StringField('ФИО', validators=[DataRequired(), Length(max=200)])
    password = PasswordField('Пароль', validators=[Length(min=8), validate_password_strength])
    confirm_password = PasswordField('Подтверждение пароля')
    email = StringField('Email', validators=[Email(), Length(max=100)])
    phone = StringField('Телефон', validators=[Length(max=20), validate_phone])
    role = SelectField('Роль', choices=[
        ('client', 'Клиент'),
        ('executor', 'Исполнитель'),
        ('secretary', 'Секретарь'),
        ('operator', 'Оператор'),
        ('admin', 'Администратор')
    ])
    notes = TextAreaField('Примечания', validators=[Length(max=500)])
    is_active = SelectField('Активен', choices=[(True, 'Да'), (False, 'Нет')],
                            coerce=lambda x: x == 'True' or x is True)
    submit = SubmitField('Создать пользователя')

    def validate_confirm_password(self, field):
        if self.password.data and field.data != self.password.data:
            raise ValidationError('Пароли не совпадают')


class DepartmentForm(FlaskForm):
    """Форма для создания/редактирования отдела"""
    name = StringField('Название отдела', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Описание (компетенции)', validators=[Length(max=1000)])
    head_name = StringField('Начальник отдела', validators=[Length(max=200)])
    email = StringField('Email отдела', validators=[Email(), Length(max=100)])
    phone = StringField('Телефон', validators=[Length(max=20), validate_phone])
    sort_order = IntegerField('Порядок сортировки', default=0)
    submit = SubmitField('Сохранить')


class CreateEmployeeUserForm(FlaskForm):
    """Форма для создания пользователя-сотрудника (одновременно пользователь + сотрудник)"""
    username = StringField('Логин', validators=[DataRequired(), Length(min=3, max=80), validate_username])
    full_name = StringField('ФИО', validators=[DataRequired(), Length(max=200)])
    email = StringField('Email', validators=[Email(), Length(max=100)])
    phone = StringField('Телефон', validators=[Length(max=20), validate_phone])
    position = StringField('Должность', validators=[DataRequired(), Length(max=200)])
    department_id = SelectField('Отдел', coerce=int, validators=[DataRequired()])
    phone_work = StringField('Рабочий телефон', validators=[Length(max=20), validate_phone])
    password = PasswordField('Пароль', validators=[Length(min=6)])
    confirm_password = PasswordField('Подтверждение пароля')
    submit = SubmitField('Создать сотрудника')

    def validate_confirm_password(self, field):
        if self.password.data and field.data != self.password.data:
            raise ValidationError('Пароли не совпадают')