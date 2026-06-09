import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from datetime import datetime
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "lumiere-super-secret-2025")

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:password@localhost/lumiere_shop")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
CATEGORIES = ["Уход за лицом", "Уход за телом", "Макияж", "Волосы", "Парфюмерия", "Другое"]

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Войдите чтобы продолжить"
login_manager.login_message_category = "info"


# ─── MODELS ───────────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    cart_items = db.relationship("CartItem", backref="user", lazy=True, cascade="all, delete-orphan")
    orders = db.relationship("Order", backref="user", lazy=True)


class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    brand = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(500), nullable=True)
    stock = db.Column(db.Integer, default=100)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CartItem(db.Model):
    __tablename__ = "cart_items"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    product = db.relationship("Product")


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    total = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship("OrderItem", backref="order", lazy=True)


class OrderItem(db.Model):
    __tablename__ = "order_items"
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    product = db.relationship("Product")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Доступ только для администратора!", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_image_url(image_url):
    if not image_url:
        return None
    if image_url.startswith("http"):
        return image_url
    return url_for("static", filename=image_url)


app.jinja_env.globals["get_image_url"] = get_image_url


def get_cart_count():
    if current_user.is_authenticated:
        return CartItem.query.filter_by(user_id=current_user.id).count()
    return 0


app.jinja_env.globals["get_cart_count"] = get_cart_count


# ─── INIT DB ──────────────────────────────────────────────────────────────────

with app.app_context():
    db.create_all()
    # Create default admin
    if not User.query.filter_by(email="admin@lumiere.kz").first():
        admin = User(
            name="Admin",
            email="admin@lumiere.kz",
            password=bcrypt.generate_password_hash("admin123").decode("utf-8"),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()


# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not name or not email or not password:
            flash("Заполните все поля!", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Пароли не совпадают!", "error")
            return render_template("register.html")
        if len(password) < 6:
            flash("Пароль минимум 6 символов!", "error")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("Email уже зарегистрирован!", "error")
            return render_template("register.html")

        user = User(
            name=name,
            email=email,
            password=bcrypt.generate_password_hash(password).decode("utf-8")
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash(f"Добро пожаловать, {name}!", "success")
        return redirect(url_for("index"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash(f"Добро пожаловать, {user.name}!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))
        flash("Неверный email или пароль!", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Вы вышли из аккаунта", "info")
    return redirect(url_for("index"))


# ─── SHOP ROUTES ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    search = request.args.get("search", "").strip()
    category = request.args.get("category", "").strip()
    sort = request.args.get("sort", "").strip()

    query = Product.query.filter_by(is_active=True)

    if search:
        query = query.filter(
            (Product.name.ilike(f"%{search}%")) |
            (Product.brand.ilike(f"%{search}%")) |
            (Product.description.ilike(f"%{search}%"))
        )
    if category:
        query = query.filter(Product.category == category)
    if sort == "price_asc":
        query = query.order_by(Product.price.asc())
    elif sort == "price_desc":
        query = query.order_by(Product.price.desc())
    elif sort == "name":
        query = query.order_by(Product.name.asc())
    else:
        query = query.order_by(Product.id.desc())

    products = query.all()
    return render_template("index.html", products=products, categories=CATEGORIES,
                           search=search, selected_category=category, sort=sort)


@app.route("/product/<int:product_id>")
def view_product(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template("view.html", product=product)


# ─── CART ROUTES ──────────────────────────────────────────────────────────────

@app.route("/cart")
@login_required
def cart():
    items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in items)
    return render_template("cart.html", items=items, total=total)


@app.route("/cart/add/<int:product_id>", methods=["POST"])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    item = CartItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if item:
        item.quantity += 1
    else:
        item = CartItem(user_id=current_user.id, product_id=product_id, quantity=1)
        db.session.add(item)
    db.session.commit()
    flash(f"{product.name} добавлен в корзину!", "success")
    return redirect(request.referrer or url_for("index"))


@app.route("/cart/remove/<int:item_id>", methods=["POST"])
@login_required
def remove_from_cart(item_id):
    item = CartItem.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        flash("Нет доступа!", "error")
        return redirect(url_for("cart"))
    db.session.delete(item)
    db.session.commit()
    flash("Товар удалён из корзины", "info")
    return redirect(url_for("cart"))


@app.route("/cart/update/<int:item_id>", methods=["POST"])
@login_required
def update_cart(item_id):
    item = CartItem.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        return redirect(url_for("cart"))
    qty = int(request.form.get("quantity", 1))
    if qty < 1:
        db.session.delete(item)
    else:
        item.quantity = qty
    db.session.commit()
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    items = CartItem.query.filter_by(user_id=current_user.id).all()
    if not items:
        flash("Корзина пуста!", "error")
        return redirect(url_for("cart"))

    total = sum(item.product.price * item.quantity for item in items)
    order = Order(user_id=current_user.id, total=total, status="confirmed")
    db.session.add(order)
    db.session.flush()

    for item in items:
        order_item = OrderItem(
            order_id=order.id,
            product_id=item.product_id,
            quantity=item.quantity,
            price=item.product.price
        )
        db.session.add(order_item)
        db.session.delete(item)

    db.session.commit()
    flash(f"Заказ №{order.id} оформлен! Сумма: {total:,.0f} ₸", "success")
    return redirect(url_for("orders"))


@app.route("/orders")
@login_required
def orders():
    user_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template("orders.html", orders=user_orders)


# ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    total_products = Product.query.count()
    total_users = User.query.filter_by(is_admin=False).count()
    total_orders = Order.query.count()
    total_revenue = db.session.query(db.func.sum(Order.total)).scalar() or 0
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()
    return render_template("admin/dashboard.html",
                           total_products=total_products,
                           total_users=total_users,
                           total_orders=total_orders,
                           total_revenue=total_revenue,
                           recent_orders=recent_orders)


@app.route("/admin/products")
@login_required
@admin_required
def admin_products():
    products = Product.query.order_by(Product.id.desc()).all()
    return render_template("admin/products.html", products=products)


@app.route("/admin/products/add", methods=["GET", "POST"])
@login_required
@admin_required
def admin_add_product():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        brand = request.form.get("brand", "").strip()
        category = request.form.get("category", "").strip()
        price = request.form.get("price", "0").strip()
        description = request.form.get("description", "").strip()
        stock = request.form.get("stock", "100").strip()
        image_link = request.form.get("image_link", "").strip()

        if not name or not brand or not category:
            flash("Заполните обязательные поля!", "error")
            return render_template("admin/product_form.html", categories=CATEGORIES, product=None)
        try:
            price = float(price)
            stock = int(stock)
        except ValueError:
            flash("Неверный формат цены или остатка!", "error")
            return render_template("admin/product_form.html", categories=CATEGORIES, product=None)

        image_url = image_link if image_link else None
        file = request.files.get("image")
        if file and file.filename and allowed_file(file.filename):
            ext = file.filename.rsplit(".", 1)[1].lower()
            filename = f"{uuid.uuid4().hex}.{ext}"
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_url = f"uploads/{filename}"

        product = Product(name=name, brand=brand, category=category,
                          price=price, description=description,
                          image_url=image_url, stock=stock)
        db.session.add(product)
        db.session.commit()
        flash("Товар добавлен!", "success")
        return redirect(url_for("admin_products"))

    return render_template("admin/product_form.html", categories=CATEGORIES, product=None)


@app.route("/admin/products/edit/<int:product_id>", methods=["GET", "POST"])
@login_required
@admin_required
def admin_edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if request.method == "POST":
        product.name = request.form.get("name", "").strip()
        product.brand = request.form.get("brand", "").strip()
        product.category = request.form.get("category", "").strip()
        product.description = request.form.get("description", "").strip()
        image_link = request.form.get("image_link", "").strip()

        try:
            product.price = float(request.form.get("price", "0"))
            product.stock = int(request.form.get("stock", "100"))
        except ValueError:
            flash("Неверный формат цены!", "error")
            return render_template("admin/product_form.html", categories=CATEGORIES, product=product)

        if image_link:
            product.image_url = image_link

        file = request.files.get("image")
        if file and file.filename and allowed_file(file.filename):
            ext = file.filename.rsplit(".", 1)[1].lower()
            filename = f"{uuid.uuid4().hex}.{ext}"
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            product.image_url = f"uploads/{filename}"

        db.session.commit()
        flash("Товар обновлён!", "success")
        return redirect(url_for("admin_products"))

    return render_template("admin/product_form.html", categories=CATEGORIES, product=product)


@app.route("/admin/products/delete/<int:product_id>", methods=["POST"])
@login_required
@admin_required
def admin_delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash("Товар удалён!", "success")
    return redirect(url_for("admin_products"))


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users)


@app.route("/admin/orders")
@login_required
@admin_required
def admin_orders():
    all_orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("admin/orders.html", orders=all_orders)


@app.route("/admin/orders/status/<int:order_id>", methods=["POST"])
@login_required
@admin_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    order.status = request.form.get("status", order.status)
    db.session.commit()
    flash("Статус обновлён!", "success")
    return redirect(url_for("admin_orders"))


if __name__ == "__main__":
    app.run(debug=True, port=8080)
