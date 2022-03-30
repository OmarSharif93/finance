import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""
    if request.method == "GET":
        purchases = db.execute(
            "SELECT symbol, SUM(shares) as totalShares FROM purchase WHERE user_id = ? GROUP BY symbol", session["user_id"])
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]['cash']
        item = {}

        for purchase in purchases:
            item[purchase['symbol']] = (lookup(purchase['symbol']))
            item[purchase['symbol']]['total'] = purchase['totalShares'] * item[purchase['symbol']]['price']
            item['grand-total'] = item.get('grand-total', 0) + item[purchase['symbol']]['total']
        grand_total = item.get('grand-total', 0) + balance
        return render_template("index.html", purchases=purchases, balance=balance, item=item, grand_total=grand_total, usd=usd)
    else:
        return redirect("addcash.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares", type=int)
        item = lookup(symbol)
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        if not symbol:
            return apology("Symbol is required")
        if shares == None:
            return apology("Shares is required")
        if item == None:
            return apology("Ivalid Symbol")
        if shares <= 0:
            return apology("Invalid Share number!")
        if item["price"] * shares > cash[0]['cash']:
            return apology("You do not have enough cash to complete the purchase")
        else:
            total_price = item["price"] * shares
            db.execute("INSERT INTO purchase (symbol, price, user_id, shares, total_price, type) VALUES (?, ?, ?, ?, ?, ?)",
                       symbol, item["price"], session["user_id"], shares, total_price, "buy")
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash[0]['cash']-total_price, session["user_id"])
            return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    items = db.execute("SELECT symbol, price, shares, bought_at, type FROM purchase WHERE user_id = ?", session["user_id"])
    return render_template("history.html", items=items)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol").upper()
        item = lookup(symbol)
        if item == None:
            return apology("No Data Avilable!")
        if not symbol:
            return apology("Symbol is required")
        else:
            return render_template("quoted.html", name=item["name"], price=item["price"], usd=usd)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        user_name = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not user_name or not password or not confirmation:
            return apology("user name and password are required")

        rows = db.execute("SELECT id FROM users WHERE username = ?", user_name)
        if len(rows) != 0:
            return apology("User already exists")
        if password != confirmation:
            return apology("password and confirm password does not match")
        if len(rows) == 0 and password == confirmation:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", user_name,
                       generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))
            return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares", type=int)
        if not symbol:
            return apology("Symbol is required")
        if shares <= 0:
            return apology("Shares must be a positive number")
        if shares == None:
            return apology("Shares is required")

        # Get total Shares from DataBase
        row = db.execute("SELECT SUM(shares) as totalShares FROM purchase WHERE user_id = ? AND symbol = ?",
                         session["user_id"], symbol)
        if row[0]['totalShares'] < shares:
            return apology("You can't sell more than you own")

        item = lookup(symbol)
        total_price = item["price"] * shares
        db.execute("INSERT INTO purchase (symbol, price, user_id, shares, total_price, type) VALUES (?, ?, ?, ?, ?, ?)",
                   symbol, item["price"], session["user_id"], -shares, total_price, "sell")
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        current_balance = total_price + cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", current_balance, session["user_id"])
        return redirect("/")
    else:
        symbols = db.execute(
            "SELECT symbol, SUM(shares) as totalShares FROM purchase WHERE user_id = ? GROUP BY symbol", session["user_id"])
        return render_template("sell.html", symbols=symbols)


@app.route("/addcash", methods=["GET", "POST"])
@login_required
def addcash():
    """ADD cash to your Balance"""
    if request.method == "POST":
        amount = request.form.get("amount", type=int)
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if amount == None:
            return apology("Amount is required")
        if amount <= 0:
            return apology("Amount must be a postive number!")
        if not password:
            return apology("Password is required!")
        if not confirmation:
            return apology("Please Confirm your password")
        if password != confirmation:
            return apology("Password must Match confirmation")
        row = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if not check_password_hash(row[0]["hash"], password):
            return apology("Wrong password!")
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", amount, session["user_id"])
        return redirect("/")
    else:
        return render_template("addcash.html")
