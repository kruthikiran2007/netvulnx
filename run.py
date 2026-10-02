"""Start the NetVulnX web application.

Run this from the project folder:
    python run.py

Then open http://127.0.0.1:5000 in your browser.

By default this uses waitress, a production-grade pure-Python server
(works on Windows, macOS and Linux). Set NETVULNX_DEBUG=1 to use Flask's
development server instead (helpful error pages, auto-reload).

Before exposing the app beyond your own machine, set a real secret key:
    NETVULNX_SECRET_KEY=<long random value>
The app warns loudly on startup if the development fallback key is in use.
"""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Recurring scans (Milestone 10): background ticker, due schedules
    # run every minute. Started here — not in the app factory — so the
    # test suite (which builds the app directly) never spawns threads.
    # With the debug reloader, run.py executes twice; only the reloaded
    # child (WERKZEUG_RUN_MAIN=true) starts the ticker.
    from scanner import scheduler as _scheduler
    _is_reloader_parent = (os.environ.get("NETVULNX_DEBUG") == "1"
                           and os.environ.get("WERKZEUG_RUN_MAIN") != "true")
    if not _is_reloader_parent:
        _scheduler.start_scheduler(app)

    if os.environ.get("NETVULNX_DEBUG") == "1":
        # Development: helpful error pages, auto-reload on code changes.
        app.run(host="127.0.0.1", port=5000, debug=True)
    else:
        # Production-grade server. host="127.0.0.1" means the app is only
        # reachable from THIS machine, not from the network.
        from waitress import serve
        print("Serving with waitress on http://127.0.0.1:5000 "
              "(NETVULNX_DEBUG=1 for the Flask dev server)")
        serve(app, host="127.0.0.1", port=5000)
