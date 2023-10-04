from flask import Flask, render_template
from flask_migrate import Migrate
from server import db
from flask import render_template
import os

app = Flask(__name__, template_folder=os.path.abspath('templates'))
app.debug = True
migrate = Migrate(app,db)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
