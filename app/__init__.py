"""Flask application factory.

An "app factory" is just a function that builds and returns the Flask app.
Why a function instead of a ready-made global object? Because tests (and the
dev server, and future scripts) can each build a fresh app whenever they want,
without side effects leaking between them.
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# The database handle. Models (in app/models.py) attach their tables to this.
db = SQLAlchemy()


def create_app(config_class=None):
    app = Flask(__name__)

    if config_class is None:
        from config import Config
        config_class = Config
    app.config.from_object(config_class)

    db.init_app(app)

    # Register all web pages / actions.
    from app import routes
    app.register_blueprint(routes.bp)

    # Create database tables on first run. (Later milestones will switch to
    # proper database migrations; create_all is fine while the schema is young.)
    with app.app_context():
        db.create_all()

    return app
