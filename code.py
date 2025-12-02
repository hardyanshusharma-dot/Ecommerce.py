"""
Simple e-commerce backend (Flask + SQLAlchemy + JWT).
Single-file example for demo / learning / GitHub repo.

Features:
- Register / Login (JWT)
- Product listing / detail
- Admin product CRUD
- Cart (order with status "cart")
- Checkout (mark order as "placed")
- Seed command to create sample products and an admin user

Run:
    pip install -r requirements.txt
    python app.py

API examples (after running on localhost:5000):
    POST /api/auth/register  { "email", "password", "name" }
    POST /api/auth/login     { "email", "password" } -> returns access_token
    GET  /api/products
    POST /api/products (admin only)
    POST /api/cart/add      (auth) body: {"product_id":1,"quantity":2}
    POST /api/cart/checkout (auth)
"""

from datetime import datetime, timedelta
from functools import wraps
import os

from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

# -------- CONFIG --------
APP_SECRET = os.environ.get("APP_SECRET", "change-this-secret")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_MINUTES = 60 * 24  # 1 day

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "ecommerce.sqlite")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# -------- MODELS --------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(180), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    orders = db.relationship("Order", backref="user", lazy=True)

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    def to_dict(self):
        return {"id": self.id, "email": self.email, "name": self.name, "is_admin": self.is_admin}


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(220), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(120), nullable=False)  # e.g., "Electronics", "Clothing"
    price_cents = db.Column(db.Integer, nullable=False, default=0)  # price in cents
    stock = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "price": self.price_cents / 100.0,
            "stock": self.stock,
            "created_at": self.created_at.isoformat()
        }


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(50), default="cart")  # cart, placed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship("OrderItem", backref="order", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "items": [i.to_dict() for i in self.items],
            "total": sum(i.quantity * i.unit_price_cents for i in self.items) / 100.0
        }


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    product_title = db.Column(db.String(220), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    unit_price_cents = db.Column(db.Integer, nullable=False)  # snapshot of price at order time

    def to_dict(self):
        return {
            "id": self.id,
            "product_id": self.product_id,
            "product_title": self.product_title,
            "quantity": self.quantity,
            "unit_price": self.unit_price_cents / 100.0,
            "line_total": (self.unit_price_cents * self.quantity) / 100.0
        }


# -------- AUTH HELPERS --------
def create_access_token(identity: dict, expires_delta: timedelta = None):
    now = datetime.utcnow()
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
    payload = {
        "sub": identity,  # identity can be a dict (we will store user id/email)
        "iat": now.timestamp(),
        "exp": (now + expires_delta).timestamp()
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGORITHM)
    # jwt.encode returns str in pyjwt>=2
    return token


def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        return None
    except Exception:
        return None


def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth_header.split(" ", 1)[1].strip()
        identity = decode_access_token(token)
        if not identity:
            return jsonify({"error": "Invalid or expired token"}), 401
        # identity is e.g. {"id": 1, "email": "..."}
        user = User.query.get(identity.get("id"))
        if not user:
            return jsonify({"error": "User not found"}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @auth_required
    def decorated(*args, **kwargs):
        user = g.current_user
        if not user.is_admin:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# -------- ROUTES --------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})


# Auth
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password")
    name = data.get("name", "")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "email already registered"}), 400
    u = User(email=email, name=name)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    token = create_access_token({"id": u.id, "email": u.email})
    return jsonify({"user": u.to_dict(), "access_token": token})


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400
    u = User.query.filter_by(email=email).first()
    if not u or not u.check_password(password):
        return jsonify({"error": "invalid credentials"}), 401
    token = create_access_token({"id": u.id, "email": u.email})
    return jsonify({"user": u.to_dict(), "access_token": token})


# Products (public)
@app.route("/api/products", methods=["GET"])
def list_products():
    # Basic filtering: category, q (search), min_price, max_price
    q = request.args.get("q", type=str)
    category = request.args.get("category", type=str)
    min_price = request.args.get("min_price", type=float)
    max_price = request.args.get("max_price", type=float)
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    query = Product.query
    if q:
        query = query.filter(Product.title.ilike(f"%{q}%"))
    if category:
        query = query.filter(Product.category == category)
    if min_price is not None:
        query = query.filter(Product.price_cents >= int(min_price * 100))
    if max_price is not None:
        query = query.filter(Product.price_cents <= int(max_price * 100))

    pagination = query.order_by(Product.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    products = [p.to_dict() for p in pagination.items]
    return jsonify({
        "products": products,
        "page": page,
        "per_page": per_page,
        "total": pagination.total
    })


@app.route("/api/products/<int:product_id>", methods=["GET"])
def get_product(product_id):
    p = Product.query.get_or_404(product_id)
    return jsonify(p.to_dict())


# Admin product CRUD
@app.route("/api/products", methods=["POST"])
@admin_required
def create_product():
    data = request.get_json() or {}
    title = data.get("title")
    category = data.get("category")
    price = data.get("price", 0.0)
    stock = data.get("stock", 0)
    description = data.get("description", "")

    if not title or not category:
        return jsonify({"error": "title and category required"}), 400

    p = Product(
        title=title,
        description=description,
        category=category,
        price_cents=int(round(float(price) * 100)),
        stock=int(stock)
    )
    db.session.add(p)
    db.session.commit()
    return jsonify(p.to_dict()), 201


@app.route("/api/products/<int:product_id>", methods=["PUT"])
@admin_required
def update_product(product_id):
    p = Product.query.get_or_404(product_id)
    data = request.get_json() or {}
    p.title = data.get("title", p.title)
    p.category = data.get("category", p.category)
    p.description = data.get("description", p.description)
    if "price" in data:
        p.price_cents = int(round(float(data["price"]) * 100))
    if "stock" in data:
        p.stock = int(data["stock"])
    db.session.commit()
    return jsonify(p.to_dict())


@app.route("/api/products/<int:product_id>", methods=["DELETE"])
@admin_required
def delete_product(product_id):
    p = Product.query.get_or_404(product_id)
    db.session.delete(p)
    db.session.commit()
    return jsonify({"deleted": True})


# CART / ORDER endpoints
def get_or_create_cart_for_user(user: User) -> Order:
    cart = Order.query.filter_by(user_id=user.id, status="cart").first()
    if cart:
        return cart
    cart = Order(user_id=user.id, status="cart")
    db.session.add(cart)
    db.session.commit()
    return cart


@app.route("/api/cart", methods=["GET"])
@auth_required
def view_cart():
    user: User = g.current_user
    cart = get_or_create_cart_for_user(user)
    return jsonify(cart.to_dict())


@app.route("/api/cart/add", methods=["POST"])
@auth_required
def add_to_cart():
    user: User = g.current_user
    data = request.get_json() or {}
    product_id = data.get("product_id")
    quantity = int(data.get("quantity", 1))
    if not product_id or quantity <= 0:
        return jsonify({"error": "product_id and positive quantity required"}), 400
    product = Product.query.get_or_404(product_id)
    if product.stock < quantity:
        return jsonify({"error": "not enough stock available"}), 400

    cart = get_or_create_cart_for_user(user)

    # try to find existing item
    item = OrderItem.query.filter_by(order_id=cart.id, product_id=product.id).first()
    if item:
        item.quantity += quantity
    else:
        item = OrderItem(
            order_id=cart.id,
            product_id=product.id,
            product_title=product.title,
            quantity=quantity,
            unit_price_cents=product.price_cents
        )
        db.session.add(item)
    db.session.commit()
    return jsonify(cart.to_dict())


@app.route("/api/cart/remove", methods=["POST"])
@auth_required
def remove_from_cart():
    user: User = g.current_user
    data = request.get_json() or {}
    item_id = data.get("item_id")
    if not item_id:
        return jsonify({"error": "item_id required"}), 400
    cart = get_or_create_cart_for_user(user)
    item = OrderItem.query.filter_by(order_id=cart.id, id=item_id).first()
    if not item:
        return jsonify({"error": "item not found in cart"}), 404
    db.session.delete(item)
    db.session.commit()
    return jsonify(cart.to_dict())


@app.route("/api/cart/checkout", methods=["POST"])
@auth_required
def checkout():
    user: User = g.current_user
    cart = get_or_create_cart_for_user(user)
    if not cart.items:
        return jsonify({"error": "cart is empty"}), 400

    # Basic stock check and decrement
    for item in cart.items:
        product = Product.query.get(item.product_id)
        if not product:
            return jsonify({"error": f"product {item.product_id} not found"}), 400
        if product.stock < item.quantity:
            return jsonify({"error": f"not enough stock for product {product.title}"}), 400

    for item in cart.items:
        product = Product.query.get(item.product_id)
        product.stock -= item.quantity

    cart.status = "placed"
    db.session.commit()
    return jsonify({"order": cart.to_dict(), "message": "Order placed successfully"}), 200


# Admin: list all orders
@app.route("/api/admin/orders", methods=["GET"])
@admin_required
def admin_list_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return jsonify([o.to_dict() for o in orders])


# -------- UTIL / CLI --------
@app.cli.command("init-db")
def init_db():
    """Initialize the database (for CLI use: python app.py init-db)"""
    db.create_all()
    print("Database initialized.")


@app.cli.command("seed")
def seed():
    """Create sample products and an admin user"""
    db.create_all()
    # create admin user
    if not User.query.filter_by(email="admin@example.com").first():
        admin = User(email="admin@example.com", name="Admin", is_admin=True)
        admin.set_password("adminpass")
        db.session.add(admin)

    # sample products
    sample_products = [
        {"title": "Smartphone Model X", "category": "Electronics", "price_cents": 69900, "stock": 10,
         "description": "A fast smartphone with excellent camera."},
        {"title": "Wireless Headphones", "category": "Electronics", "price_cents": 19900, "stock": 25,
         "description": "Noise-cancelling over-ear headphones."},
        {"title": "Men's T-Shirt - Classic", "category": "Clothing", "price_cents": 1999, "stock": 100,
         "description": "Comfortable cotton tee."},
        {"title": "Women's Jacket", "category": "Clothing", "price_cents": 8999, "stock": 50,
         "description": "Warm and fashionable jacket."},
    ]
    for sp in sample_products:
        if not Product.query.filter_by(title=sp["title"]).first():
            p = Product(
                title=sp["title"],
                category=sp["category"],
                description=sp.get("description"),
                price_cents=sp["price_cents"],
                stock=sp["stock"]
            )
            db.session.add(p)
    db.session.commit()
    print("Seeded database with admin user (admin@example.com / adminpass) and sample products.")


# If run directly, support simple CLI commands: init-db and seed
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        # allow running cli commands directly: python app.py init-db
        cmd = sys.argv[1]
        if cmd == "init-db":
            with app.app_context():
                init_db()
            sys.exit(0)
        if cmd == "seed":
            with app.app_context():
                seed()
            sys.exit(0)
    # ensure DB exists
    with app.app_context():
        db.create_all()
    print("Starting development server on http://127.0.0.1:5000")
    app.run(debug=True)
