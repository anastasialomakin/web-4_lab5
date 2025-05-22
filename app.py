import os
import re
from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_migrate import Migrate
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp, ValidationError
from extensions import db, login_manager
from models import Role, User, VisitLog

# конфига
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_very_secret_key_replace_in_production_for_real')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# application = app # Для WSGI

# инициализация бд и менеджер логинов
db.init_app(app)
migrate = Migrate(app, db) # Migrate инициализируется с app и db
login_manager.init_app(app) # LoginManager инициализируется с app
login_manager.login_view = 'login'
login_manager.login_message = "Для доступа к этой странице необходимо войти."
login_manager.login_message_category = "info"

# Импорт декораторов ДО моделей или блюпринтов
from decorators import check_rights

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# валидатор
def password_complexity_validator(form, field):
    password = field.data
    errors = []
    if not re.search(r"[A-ZА-Я]", password):
        errors.append("Пароль должен содержать хотя бы одну заглавную букву.")
    if not re.search(r"[a-zа-я]", password):
        errors.append("Пароль должен содержать хотя бы одну строчную букву.")
    if not re.search(r"\d", password):
        errors.append("Пароль должен содержать хотя бы одну арабскую цифру.")
    if re.search(r"\s", password):
        errors.append("Пароль не должен содержать пробелов.")
    
    allowed_chars_pattern = r"^[a-zA-Zа-яА-Я0-9~!?@#$%^&*_\-+=()[\]{}><\/\\|\"'.,:;]*$"
    if not re.match(allowed_chars_pattern, password):
        errors.append("Пароль содержит недопустимые символы.")
    
    if errors:
        raise ValidationError(" ".join(errors))

# Формы
class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(message="Поле не может быть пустым")])
    password = PasswordField('Пароль', validators=[DataRequired(message="Пароль не может быть пустым")])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

class UserForm(FlaskForm):
    username = StringField('Логин', validators=[
        DataRequired(message="Поле 'Логин' не может быть пустым."),
        Length(min=5, message="Логин должен быть не менее 5 символов."),
        Regexp(r'^[a-zA-Z0-9]+$', message="Логин должен состоять только из латинских букв и цифр.")
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(message="Поле 'Пароль' не может быть пустым."),
        Length(min=8, max=128, message="Пароль должен быть от 8 до 128 символов."),
        password_complexity_validator
    ])
    first_name = StringField('Имя', validators=[DataRequired(message="Поле 'Имя' не может быть пустым.")])
    last_name = StringField('Фамилия') 
    middle_name = StringField('Отчество') 
    role = SelectField('Роль', coerce=int, validate_choice=False) 
    submit = SubmitField('Сохранить')

    def __init__(self, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        self.role.choices = [(0, '--- Без роли ---')] 



class UserEditForm(FlaskForm):
    first_name = StringField('Имя', validators=[DataRequired(message="Поле 'Имя' не может быть пустым.")])
    last_name = StringField('Фамилия')
    middle_name = StringField('Отчество')
    role = SelectField('Роль', coerce=int, validate_choice=False)
    submit = SubmitField('Сохранить изменения')

    def __init__(self, *args, **kwargs):
        super(UserEditForm, self).__init__(*args, **kwargs)
        self.role.choices = [(0, '--- Без роли ---')]

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Старый пароль', validators=[DataRequired(message="Это поле обязательно.")])
    new_password = PasswordField('Новый пароль', validators=[
        DataRequired(message="Это поле обязательно."),
        Length(min=8, max=128, message="Пароль должен быть от 8 до 128 символов."),
        password_complexity_validator
    ])
    confirm_new_password = PasswordField('Повторите новый пароль', validators=[
        DataRequired(message="Это поле обязательно."),
        EqualTo('new_password', message='Пароли должны совпадать.')
    ])
    submit = SubmitField('Изменить пароль')

class DeleteUserForm(FlaskForm):
    submit = SubmitField('Да, удалить')

# Контекстный процессор и before_request
@app.context_processor
def utility_processor():
    def user_can(action, resource_user_id=None):
        if not current_user.is_authenticated:
            return False

        user_role_name = current_user.role.name if current_user.role else None

        # Администратор
        if user_role_name == 'Администратор':
            if action == "create_user": return True
            if action == "edit_any_user": return True
            if action == "view_any_user": return True
            if action == "delete_any_user":
                return resource_user_id is None or int(resource_user_id) != current_user.id
            if action == "view_visit_log_page": return True
            if action == "view_detailed_reports": return True # For /by_page, /by_user links & pages

        # Пользователь
        elif user_role_name == 'Пользователь':
            if action == "edit_own_user" and resource_user_id and int(resource_user_id) == current_user.id: return True
            if action == "view_own_user" and resource_user_id and int(resource_user_id) == current_user.id: return True
            if action == "view_visit_log_page": return True
        
        return False
    return dict(user_can=user_can)

@app.before_request
def log_visit():
    if request.endpoint and (request.endpoint.startswith('static') or 'export' in request.endpoint or request.endpoint == 'visits' or request.blueprint == 'debugtoolbar'): 
        return

    path = request.path
    user_id = current_user.id if current_user.is_authenticated else None
    
    try:
        visit = VisitLog(path=path, user_id=user_id)
        db.session.add(visit)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error logging visit: {e}") 

# Маршруты основного приложения
@app.route('/')
def index():
    users = User.query.order_by(User.created_at.desc()).all()
    delete_form = DeleteUserForm() 
    return render_template('index.html', users=users, delete_form=delete_form)

@app.route('/visits')
def visits():
    session['visits'] = session.get('visits', 0) + 1
    return render_template('visits.html', visits=session['visits'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            flash('Вы успешно вошли!', 'success')
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                 next_page = url_for('index')
            return redirect(next_page)
        else:
            flash('Неверный логин или пароль.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html')

# CRUD
@app.route('/users/new', methods=['GET', 'POST'])
@login_required
@check_rights("create_user")
def create_user():
    form = UserForm()
    with app.app_context(): 
        form.role.choices = [(0, '--- Без роли ---')] + [(r.id, r.name) for r in Role.query.order_by('name').all()]

    if form.validate_on_submit():
        try:
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                form.username.errors.append("Пользователь с таким логином уже существует.")
                flash('Ошибка при создании пользователя. Проверьте данные.', 'danger')
                return render_template('user_form_page.html', form=form, title="Создание пользователя", is_edit=False, user_id_being_edited=None, disable_role_field=False)

            new_user = User(
                username=form.username.data,
                first_name=form.first_name.data,
                last_name=form.last_name.data or None, 
                middle_name=form.middle_name.data or None,
                role_id=form.role.data if form.role.data != 0 else None 
            )
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash(f'Пользователь {new_user.username} успешно создан!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Ошибка при создании пользователя: {str(e)}')
            flash(f'Ошибка при создании пользователя: {str(e)}', 'danger')
    elif request.method == 'POST': 
        flash('Ошибка при создании пользователя. Проверьте введенные данные.', 'danger')

    return render_template('user_form_page.html', form=form, title="Создание пользователя", is_edit=False, user_id_being_edited=None, disable_role_field=False)


@app.route('/users/<int:user_id>/view')
@login_required
@check_rights("view_user", resource_id_param="user_id")
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_view.html', user=user)

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@check_rights("edit_user", resource_id_param="user_id")
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user_to_edit) 
    with app.app_context():
        form.role.choices = [(0, '--- Без роли ---')] + [(r.id, r.name) for r in Role.query.order_by('name').all()]


    disable_role_field = False
    if current_user.role and current_user.role.name == 'Пользователь' and user_to_edit.id == current_user.id:
        disable_role_field = True

    if request.method == 'GET':
        form.role.data = user_to_edit.role_id if user_to_edit.role_id is not None else 0

    if form.validate_on_submit():
        try:
            user_to_edit.first_name = form.first_name.data
            user_to_edit.last_name = form.last_name.data or None
            user_to_edit.middle_name = form.middle_name.data or None
            if not disable_role_field: 
                user_to_edit.role_id = form.role.data if form.role.data != 0 else None
            db.session.commit()
            flash(f'Данные пользователя {user_to_edit.username} успешно обновлены!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Ошибка при обновлении пользователя: {str(e)}')
            flash(f'Ошибка при обновлении пользователя: {str(e)}', 'danger')
    elif request.method == 'POST': 
         flash('Ошибка при обновлении пользователя. Проверьте введенные данные.', 'danger')

    return render_template('user_form_page.html', form=form, title=f"Редактирование: {user_to_edit.get_fio()}", user=user_to_edit, is_edit=True, user_id_being_edited=user_to_edit.id, disable_role_field=disable_role_field)


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@check_rights("delete_user", resource_id_param="user_id")
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id : 
        flash('Вы не можете удалить свою учетную запись.', 'warning')
        return redirect(url_for('index'))
    try:
        fio = user_to_delete.get_fio()
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'Пользователь {fio} успешно удален.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Ошибка при удалении пользователя: {str(e)}')
        flash(f'Ошибка при удалении пользователя: {str(e)}', 'danger')
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.old_password.data):
            try:
                current_user.set_password(form.new_password.data)
                db.session.commit()
                flash('Пароль успешно изменен.', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Ошибка при смене пароля: {str(e)}')
                flash(f'Ошибка при смене пароля: {str(e)}', 'danger')
        else:
            form.old_password.errors.append('Неверный старый пароль.')
    elif request.method == 'POST' and not form.validate(): 
        flash('Ошибка при смене пароля. Проверьте введенные данные.', 'danger')


    return render_template('change_password.html', form=form, title="Изменение пароля")


# Импорт и регистрация блюпринта ПОСЛЕ ВСЕХ @app.route
from reports import reports_bp  # reports_bp определяется в reports/__init__.py
app.register_blueprint(reports_bp)

# Функция для создания первоначальных ролей и администратора
def create_initial_roles_and_admin():
    with app.app_context(): 
        db.create_all()
        if Role.query.count() == 0:
            print("Creating initial roles...")
            admin_role = Role(name='Администратор', description='Полный доступ к системе')
            user_role = Role(name='Пользователь', description='Стандартные права пользователя')
            db.session.add_all([admin_role, user_role])
            db.session.commit()
            print("Roles created.")
        else:
            print("Roles already exist.")
            admin_role = Role.query.filter_by(name='Администратор').first()

        if User.query.filter_by(username='admin').first() is None:
            print("Creating admin user...")
            if not admin_role:
                 admin_role = Role.query.filter_by(name='Администратор').first()
            admin_user = User(username='admin', first_name='Админ', role_id=admin_role.id if admin_role else None)
            admin_user.set_password('Admin123!')
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created. Login: admin, Password: Admin123!")
        else:
            print("Admin user already exists.")

if __name__ == '__main__':
    create_initial_roles_and_admin()
    app.run(debug=True)
