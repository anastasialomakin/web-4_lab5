from functools import wraps
from flask import flash, redirect, url_for, request
from flask_login import current_user

def check_rights(action, resource_id_param=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Для доступа к этой странице необходимо войти.", "info")
                return redirect(url_for('login', next=request.url))

            target_resource_id = kwargs.get(resource_id_param) if resource_id_param else None
            
            has_permission = False
            user_role_name = current_user.role.name if current_user.role else None

            # права администратора
            if user_role_name == 'Администратор':
                if action == "create_user": has_permission = True
                elif action == "edit_user": has_permission = True 
                elif action == "view_user": has_permission = True 
                elif action == "delete_user":
                    if target_resource_id and int(target_resource_id) != current_user.id:
                        has_permission = True
                elif action in ["view_visit_log_page", "view_detailed_reports"]: 
                    has_permission = True
            
            # права пользователя
            elif user_role_name == 'Пользователь':
                if action == "edit_user":
                    if target_resource_id and int(target_resource_id) == current_user.id:
                        has_permission = True
                elif action == "view_user":
                    if target_resource_id and int(target_resource_id) == current_user.id:
                        has_permission = True
                elif action == "view_visit_log_page": 
                    has_permission = True
            
            if not has_permission:
                flash("У вас недостаточно прав для доступа к данной странице.", "danger")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator