"""Start the NetVulnX web application (development server).

Run this from the project folder:
    python run.py

Then open http://127.0.0.1:5000 in your browser.
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # host="127.0.0.1" means the app is only reachable from THIS machine,
    # not from the network. debug=True gives helpful error pages while learning.
    app.run(host="127.0.0.1", port=5000, debug=True)
