# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import numpy as np

app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['SESSION_COOKIE_SECURE'] = False

# Dummy user database (hashed passwords)
users = {
    "admin": generate_password_hash("admin123"),
    "sam": generate_password_hash("mypassword")
}

# Load the trained ML model
model = joblib.load('model/tax_evasion_model.pkl')

@app.route('/', methods=["GET", "POST"])
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        try:
            income = float(request.form["income"])
            expenses = float(request.form["expenses"])
            expected_tax = float(request.form["Expected_Tax"])
            tax_paid = float(request.form["ActualTaxPaid"])

            # Calculate logic
            tax_discrepancy = expected_tax - tax_paid
            tcp = (tax_paid / expected_tax) * 100 if expected_tax > 0 else 0
            remaining_balance = income - expenses - tax_paid

            if tcp < 80:
                flag = "Potential Tax Evasion"
                message = "⚠️ This account shows signs of potential tax evasion."
            else:
                flag = "Compliant"
                message = "✅ This taxpayer appears compliant."

            return render_template("index.html",
                                   username=session['username'],
                                   show_result=True,
                                   message=message,
                                   flag=flag,
                                   income=income,
                                   expected_tax=expected_tax,
                                   tax_paid=tax_paid,
                                   tax_discrepancy=tax_discrepancy,
                                   expenses=expenses,
                                   remaining_balance=remaining_balance,
                                   tcp=round(tcp, 2))
        except Exception as e:
            return render_template("index.html",
                                   username=session['username'],
                                   show_result=False,
                                   error=str(e))

    return render_template("index.html", username=session['username'], show_result=False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ✅ Accept any username and password
        session['username'] = username
        flash(f'Logged in as {username}', 'success')
        return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
