from flask_migrate import Migrate
from . import create_app, db
from flask import render_template

app = create_app()
app.debug = True
migrate = Migrate(app,db)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
