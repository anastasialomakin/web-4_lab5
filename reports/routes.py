from flask import render_template, request, redirect, url_for, flash, Response
from flask_login import login_required, current_user
from . import reports_bp
from extensions import db  # импорт db
from models import VisitLog, User  # импорт моделей
from decorators import check_rights
from sqlalchemy import func, desc
import io
import csv

REPORTS_PER_PAGE = 15

@reports_bp.route('/')
@login_required
@check_rights("view_visit_log_page")
def visit_log_index():
    page = request.args.get('page', 1, type=int)
    query = VisitLog.query
    if current_user.role and current_user.role.name == 'Пользователь':
        query = query.filter_by(user_id=current_user.id)
    logs = query.order_by(VisitLog.created_at.desc()).paginate(page=page, per_page=REPORTS_PER_PAGE, error_out=False)
    return render_template('reports/visit_log_index.html', logs=logs, title="Журнал посещений")

@reports_bp.route('/by_page')
@login_required
@check_rights("view_detailed_reports")
def report_by_page():
    page_stats = db.session.query(
        VisitLog.path,
        func.count(VisitLog.path).label('visit_count')
    ).group_by(VisitLog.path).order_by(desc('visit_count')).all()
    
    return render_template('reports/report_by_page.html', stats=page_stats, title="Статистика по страницам")

@reports_bp.route('/by_page/export_csv')
@login_required
@check_rights("view_detailed_reports") 
def export_by_page_csv():
    page_stats = db.session.query(
        VisitLog.path,
        func.count(VisitLog.path).label('visit_count')
    ).group_by(VisitLog.path).order_by(desc('visit_count')).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Страница', 'Количество посещений'])
    for stat in page_stats:
        writer.writerow([stat.path, stat.visit_count])
    
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=report_by_page.csv"}
    )

@reports_bp.route('/by_user')
@login_required
@check_rights("view_detailed_reports")
def report_by_user():
    auth_user_stats_query = db.session.query(
        User.id.label('user_id'), 
        User.first_name,
        User.last_name,
        User.middle_name,
        User.username,
        func.count(VisitLog.id).label('visit_count')
    ).join(VisitLog, VisitLog.user_id == User.id)\
    .group_by(User.id, User.first_name, User.last_name, User.middle_name, User.username)\
    .order_by(desc('visit_count')).all()
    
    processed_stats = []
    for stat in auth_user_stats_query:
        fio_parts = [stat.last_name, stat.first_name, stat.middle_name]
        fio = " ".join(p for p in fio_parts if p) or stat.username
        processed_stats.append({'fio': fio, 'visit_count': stat.visit_count})

    unauth_visits_count = db.session.query(func.count(VisitLog.id))\
                                  .filter(VisitLog.user_id.is_(None)).scalar() or 0
    if unauth_visits_count > 0:
         processed_stats.append({'fio': "Неаутентифицированный пользователь", 'visit_count': unauth_visits_count})
    
    processed_stats.sort(key=lambda x: x['visit_count'], reverse=True)

    return render_template('reports/report_by_user.html', stats=processed_stats, title="Статистика по пользователям")


@reports_bp.route('/by_user/export_csv')
@login_required
@check_rights("view_detailed_reports")
def export_by_user_csv():
    auth_user_stats_query = db.session.query(
        User.first_name,
        User.last_name,
        User.middle_name,
        User.username,
        func.count(VisitLog.id).label('visit_count')
    ).join(VisitLog, VisitLog.user_id == User.id)\
    .group_by(User.id, User.first_name, User.last_name, User.middle_name, User.username)\
    .order_by(desc('visit_count')).all()

    processed_stats_for_csv = []
    for stat in auth_user_stats_query:
        fio_parts = [stat.last_name, stat.first_name, stat.middle_name]
        fio = " ".join(p for p in fio_parts if p) or stat.username
        processed_stats_for_csv.append({'fio': fio, 'visit_count': stat.visit_count})
    
    unauth_visits_count = db.session.query(func.count(VisitLog.id))\
                                  .filter(VisitLog.user_id.is_(None)).scalar() or 0
    if unauth_visits_count > 0:
         processed_stats_for_csv.append({'fio': "Неаутентифицированный пользователь", 'visit_count': unauth_visits_count})
    
    processed_stats_for_csv.sort(key=lambda x: x['visit_count'], reverse=True)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Пользователь', 'Количество посещений'])
    for stat_item in processed_stats_for_csv:
        writer.writerow([stat_item['fio'], stat_item['visit_count']])
    
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=report_by_user.csv"}
    )
