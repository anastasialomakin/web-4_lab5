from flask import Blueprint

reports_bp = Blueprint('reports', __name__, template_folder='../templates', url_prefix='/reports')

from . import routes
