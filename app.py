import uuid
from flask_socketio import SocketIO, emit, join_room
from functools import wraps
import os, re, sqlite3
from datetime import timedelta
from flask import (Flask, g, render_template, request, redirect,
                   url_for, session, flash, abort)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

import db as database

REPORT_THRESHOLD = 3

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or os.urandom(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("PRODUCTION") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
)

csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins=[])
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])
ph = PasswordHasher()
UPLOAD_DIR = os.path.join(app.root_path, "static", "uploads")
ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
MAX_PRICE = 1_000_000_000

# 확장자가 아닌 실제 파일 시그니처(매직 바이트)로 판별
MAGIC = {
    b"\xff\xd8\xff": ".jpg",
    b"\x89PNG\r\n\x1a\n": ".png",
    b"GIF87a": ".gif",
    b"GIF89a": ".gif",
}


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def save_image(fs):
    """이미지 검증 후 저장. 실패 시 None"""
    if not fs or not fs.filename:
        return None

    if os.path.splitext(fs.filename)[1].lower() not in ALLOWED_EXT:
        return None

    head = fs.stream.read(12)
    fs.stream.seek(0)

    real_ext = None
    for sig, e in MAGIC.items():
        if head.startswith(sig):
            real_ext = e
            break
    if real_ext is None and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        real_ext = ".webp"
    if real_ext is None:
        return None

    name = f"{uuid.uuid4().hex}{real_ext}"
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    fs.save(os.path.join(UPLOAD_DIR, name))
    return name


def validate_product_form():
    """(title, desc, price) 또는 (None, 에러메시지, None)"""
    title = request.form.get("title", "").strip()
    desc = request.form.get("description", "").strip()
    price = request.form.get("price", "").strip()

    if not (1 <= len(title) <= 100):
        return None, "상품명은 1~100자여야 합니다.", None
    if len(desc) > 2000:
        return None, "설명은 2000자 이하여야 합니다.", None
    if not price.isdigit() or int(price) > MAX_PRICE:
        return None, "가격은 0 이상의 정수여야 합니다.", None
    return title, desc, int(price)


def owned_product(pid):
    row = database.get_db().execute(
        "SELECT * FROM product WHERE id = ?", (pid,)).fetchone()
    if row is None:
        abort(404)
    if row["seller_id"] != current_user()["id"]:
        abort(403)
    return row

app.teardown_appcontext(database.close_db)

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return database.get_db().execute(
        "SELECT * FROM user WHERE id = ?", (uid,)
    ).fetchone()


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not USERNAME_RE.match(username):
            flash("아이디는 영문/숫자/_ 3~20자여야 합니다.")
            return redirect(url_for("register"))
        if len(password) < 8:
            flash("비밀번호는 8자 이상이어야 합니다.")
            return redirect(url_for("register"))

        conn = database.get_db()
        try:
            conn.execute(
                "INSERT INTO user (username, password_hash) VALUES (?, ?)",
                (username, ph.hash(password)),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("이미 사용 중인 아이디입니다.")
            return redirect(url_for("register"))

        flash("가입 완료. 로그인해주세요.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        row = database.get_db().execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        try:
            if row is None:
                raise VerifyMismatchError
            ph.verify(row["password_hash"], password)
        except (VerifyMismatchError, VerificationError):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
            return redirect(url_for("login"))

        if row["is_dormant"]:
            flash("휴면 계정입니다. 관리자에게 문의하세요.")
            return redirect(url_for("login"))

        session.clear()
        session["user_id"] = row["id"]
        session.permanent = True
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/products")
def products():
    q = request.args.get("q", "").strip()[:50]
    db = database.get_db()
    if q:
        like = f"%{q}%"
        rows = db.execute(
            "SELECT id, title FROM product WHERE is_blocked = 0 "
            "AND (title LIKE ? OR description LIKE ?) "
            "ORDER BY id DESC LIMIT 100", (like, like)).fetchall()
    else:
        rows = db.execute(
            "SELECT id, title FROM product WHERE is_blocked = 0 "
            "ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("products.html", products=rows, q=q)


@app.route("/product/<int:pid>")
def product_detail(pid):
    row = database.get_db().execute(
        "SELECT p.*, u.username AS seller FROM product p "
        "JOIN user u ON u.id = p.seller_id WHERE p.id = ?", (pid,)).fetchone()
    if row is None or row["is_blocked"]:
        abort(404)
    return render_template("product_detail.html", p=row)


@app.route("/product/new", methods=["GET", "POST"])
@login_required
@limiter.limit("20 per hour", methods=["POST"])
def product_new():
    if request.method == "POST":
        title, desc, price = validate_product_form()
        if title is None:
            flash(desc)
            return redirect(url_for("product_new"))

        image = save_image(request.files.get("image"))
        db = database.get_db()
        db.execute(
            "INSERT INTO product (title, description, price, image_path, seller_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (title, desc, price, image, current_user()["id"]))
        db.commit()
        return redirect(url_for("my_products"))
    return render_template("product_new.html")


@app.route("/product/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def product_edit(pid):
    row = owned_product(pid)
    if request.method == "POST":
        title, desc, price = validate_product_form()
        if title is None:
            flash(desc)
            return redirect(url_for("product_edit", pid=pid))

        db = database.get_db()
        image = save_image(request.files.get("image"))
        if image:
            db.execute("UPDATE product SET title=?, description=?, price=?, "
                       "image_path=? WHERE id=? AND seller_id=?",
                       (title, desc, price, image, pid, current_user()["id"]))
        else:
            db.execute("UPDATE product SET title=?, description=?, price=? "
                       "WHERE id=? AND seller_id=?",
                       (title, desc, price, pid, current_user()["id"]))
        db.commit()
        return redirect(url_for("product_detail", pid=pid))
    return render_template("product_edit.html", p=row)


@app.route("/product/<int:pid>/delete", methods=["POST"])
@login_required
def product_delete(pid):
    owned_product(pid)
    db = database.get_db()
    db.execute("DELETE FROM product WHERE id = ? AND seller_id = ?",
               (pid, current_user()["id"]))
    db.commit()
    return redirect(url_for("my_products"))


@app.route("/my/products")
@login_required
def my_products():
    rows = database.get_db().execute(
        "SELECT * FROM product WHERE seller_id = ? ORDER BY id DESC",
        (current_user()["id"],)).fetchall()
    return render_template("my_products.html", products=rows)

@app.route("/user/<int:uid>")
@login_required
def user_profile(uid):
    row = database.get_db().execute(
        "SELECT id, username, bio, is_dormant FROM user WHERE id = ?",
        (uid,)).fetchone()
    if row is None:
        abort(404)
    return render_template("user_profile.html", u=row)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    me = current_user()
    db = database.get_db()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "bio":
            bio = request.form.get("bio", "").strip()
            if len(bio) > 500:
                flash("소개글은 500자 이하여야 합니다.")
                return redirect(url_for("profile"))
            db.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, me["id"]))
            db.commit()
            flash("소개글을 수정했습니다.")

        elif action == "password":
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")

            try:
                ph.verify(me["password_hash"], current)
            except (VerifyMismatchError, VerificationError):
                flash("현재 비밀번호가 올바르지 않습니다.")
                return redirect(url_for("profile"))

            if len(new) < 8:
                flash("새 비밀번호는 8자 이상이어야 합니다.")
                return redirect(url_for("profile"))
            if new == current:
                flash("현재 비밀번호와 다르게 설정해주세요.")
                return redirect(url_for("profile"))

            db.execute("UPDATE user SET password_hash = ? WHERE id = ?",
                       (ph.hash(new), me["id"]))
            db.commit()
            session.clear()
            flash("비밀번호를 변경했습니다. 다시 로그인해주세요.")
            return redirect(url_for("login"))

        return redirect(url_for("profile"))

    return render_template("profile.html", me=me)

@app.route("/chat")
@login_required
def chat():
    rows = database.get_db().execute(
        "SELECT m.content, u.username FROM message m "
        "JOIN user u ON u.id = m.sender_id "
        "WHERE m.receiver_id IS NULL ORDER BY m.id DESC LIMIT 50").fetchall()
    return render_template("chat.html", history=list(reversed(rows)))


@app.route("/chat/<int:uid>")
@login_required
def chat_direct(uid):
    me = current_user()
    if uid == me["id"]:
        abort(400)
    other = database.get_db().execute(
        "SELECT id, username FROM user WHERE id = ?", (uid,)).fetchone()
    if other is None:
        abort(404)

    rows = database.get_db().execute(
        "SELECT m.content, u.username FROM message m "
        "JOIN user u ON u.id = m.sender_id "
        "WHERE (m.sender_id=? AND m.receiver_id=?) "
        "   OR (m.sender_id=? AND m.receiver_id=?) "
        "ORDER BY m.id DESC LIMIT 50",
        (me["id"], uid, uid, me["id"])).fetchall()
    return render_template("chat_direct.html", other=other,
                           history=list(reversed(rows)))

@app.route("/users")
@login_required
def users():
    rows = database.get_db().execute(
        "SELECT id, username FROM user WHERE id != ? AND is_dormant = 0 "
        "ORDER BY username LIMIT 100", (current_user()["id"],)).fetchall()
    return render_template("users.html", users=rows)

def dm_room(a, b):
    return f"dm-{min(a, b)}-{max(a, b)}"

@app.route("/report", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour", methods=["POST"])
def report():
    me = current_user()
    db = database.get_db()

    if request.method == "POST":
        target_type = request.form.get("target_type", "")
        target_id = request.form.get("target_id", "").strip()
        reason = request.form.get("reason", "").strip()

        if target_type not in ("user", "product"):
            flash("잘못된 신고 대상입니다.")
            return redirect(url_for("report"))
        if not target_id.isdigit():
            flash("대상 번호가 올바르지 않습니다.")
            return redirect(url_for("report"))
        if not (5 <= len(reason) <= 500):
            flash("신고 사유는 5~500자여야 합니다.")
            return redirect(url_for("report"))

        target_id = int(target_id)

        if target_type == "user":
            if target_id == me["id"]:
                flash("자기 자신은 신고할 수 없습니다.")
                return redirect(url_for("report"))
            exists = db.execute("SELECT 1 FROM user WHERE id = ?",
                                (target_id,)).fetchone()
        else:
            exists = db.execute("SELECT 1 FROM product WHERE id = ?",
                                (target_id,)).fetchone()
        if exists is None:
            flash("존재하지 않는 대상입니다.")
            return redirect(url_for("report"))

        try:
            db.execute(
                "INSERT INTO report (reporter_id, target_type, target_id, reason) "
                "VALUES (?, ?, ?, ?)",
                (me["id"], target_type, target_id, reason))
            db.commit()
        except sqlite3.IntegrityError:
            flash("이미 신고한 대상입니다.")
            return redirect(url_for("report"))

        apply_block(target_type, target_id)
        flash("신고가 접수되었습니다.")
        return redirect(url_for("report"))

    prefill_type = request.args.get("type", "")
    prefill_id = request.args.get("id", "")
    return render_template("report.html",
                           prefill_type=prefill_type if prefill_type in ("user", "product") else "",
                           prefill_id=prefill_id if prefill_id.isdigit() else "")


def apply_block(target_type, target_id):
    """신고 누적 임계치 도달 시 자동 차단/휴면"""
    db = database.get_db()
    cnt = db.execute(
        "SELECT COUNT(*) AS c FROM report WHERE target_type = ? AND target_id = ?",
        (target_type, target_id)).fetchone()["c"]

    if cnt < REPORT_THRESHOLD:
        return

    if target_type == "product":
        db.execute("UPDATE product SET is_blocked = 1 WHERE id = ?", (target_id,))
    else:
        db.execute("UPDATE user SET is_dormant = 1 WHERE id = ? AND is_admin = 0",
                   (target_id,))
    db.commit()

MAX_TRANSFER = 100_000_000


@app.route("/transfer", methods=["GET", "POST"])
@login_required
@limiter.limit("30 per hour", methods=["POST"])
def transfer():
    me = current_user()
    db = database.get_db()

    if request.method == "POST":
        to_name = request.form.get("to_username", "").strip()
        amount_raw = request.form.get("amount", "").strip()

        if not amount_raw.isdigit():
            flash("금액은 1 이상의 정수여야 합니다.")
            return redirect(url_for("transfer"))
        amount = int(amount_raw)
        if not (1 <= amount <= MAX_TRANSFER):
            flash("송금 가능 금액 범위를 벗어났습니다.")
            return redirect(url_for("transfer"))

        target = db.execute("SELECT id, username FROM user WHERE username = ?",
                            (to_name,)).fetchone()
        if target is None:
            flash("존재하지 않는 사용자입니다.")
            return redirect(url_for("transfer"))
        if target["id"] == me["id"]:
            flash("자기 자신에게는 송금할 수 없습니다.")
            return redirect(url_for("transfer"))

        try:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                "UPDATE user SET balance = balance - ? "
                "WHERE id = ? AND balance >= ?",
                (amount, me["id"], amount))
            if cur.rowcount != 1:
                db.rollback()
                flash("잔액이 부족합니다.")
                return redirect(url_for("transfer"))

            db.execute("UPDATE user SET balance = balance + ? WHERE id = ?",
                       (amount, target["id"]))
            db.execute("INSERT INTO transfer (from_id, to_id, amount) "
                       "VALUES (?, ?, ?)", (me["id"], target["id"], amount))
            db.commit()
        except sqlite3.Error:
            db.rollback()
            flash("송금 처리 중 오류가 발생했습니다.")
            return redirect(url_for("transfer"))

        flash(f"{target['username']}님에게 {amount}원을 송금했습니다.")
        return redirect(url_for("transfer"))

    history = db.execute(
        "SELECT t.amount, t.created_at, "
        "  sender.username AS from_name, receiver.username AS to_name, "
        "  t.from_id, t.to_id "
        "FROM transfer t "
        "JOIN user sender ON sender.id = t.from_id "
        "JOIN user receiver ON receiver.id = t.to_id "
        "WHERE t.from_id = ? OR t.to_id = ? "
        "ORDER BY t.id DESC LIMIT 30", (me["id"], me["id"])).fetchall()

    return render_template("transfer.html", me=me, history=history)


@app.route("/charge", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def charge():
    """테스트용 잔액 충전"""
    db = database.get_db()
    db.execute("UPDATE user SET balance = balance + 10000 WHERE id = ?",
               (current_user()["id"],))
    db.commit()
    flash("10,000원이 충전되었습니다.")
    return redirect(url_for("transfer"))

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        me = current_user()
        if not me:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        if not me["is_admin"]:
            abort(403)
        return f(*args, **kwargs)
    return wrapper


@app.route("/admin")
@admin_required
def admin_index():
    db = database.get_db()
    users = db.execute(
        "SELECT id, username, balance, is_admin, is_dormant "
        "FROM user ORDER BY id").fetchall()
    products = db.execute(
        "SELECT p.id, p.title, p.price, p.is_blocked, u.username AS seller "
        "FROM product p JOIN user u ON u.id = p.seller_id "
        "ORDER BY p.id DESC").fetchall()
    reports = db.execute(
        "SELECT r.id, r.target_type, r.target_id, r.reason, r.created_at, "
        "       u.username AS reporter "
        "FROM report r JOIN user u ON u.id = r.reporter_id "
        "ORDER BY r.id DESC LIMIT 100").fetchall()
    return render_template("admin.html", users=users,
                           products=products, reports=reports)


@app.route("/admin/user/<int:uid>/dormant", methods=["POST"])
@admin_required
def admin_toggle_dormant(uid):
    db = database.get_db()
    row = db.execute("SELECT id, is_admin, is_dormant FROM user WHERE id = ?",
                     (uid,)).fetchone()
    if row is None:
        abort(404)
    if row["is_admin"]:
        flash("관리자 계정은 휴면 처리할 수 없습니다.")
        return redirect(url_for("admin_index"))

    db.execute("UPDATE user SET is_dormant = ? WHERE id = ?",
               (0 if row["is_dormant"] else 1, uid))
    db.commit()
    flash("계정 상태를 변경했습니다.")
    return redirect(url_for("admin_index"))


@app.route("/admin/product/<int:pid>/block", methods=["POST"])
@admin_required
def admin_toggle_block(pid):
    db = database.get_db()
    row = db.execute("SELECT id, is_blocked FROM product WHERE id = ?",
                     (pid,)).fetchone()
    if row is None:
        abort(404)
    db.execute("UPDATE product SET is_blocked = ? WHERE id = ?",
               (0 if row["is_blocked"] else 1, pid))
    db.commit()
    flash("상품 상태를 변경했습니다.")
    return redirect(url_for("admin_index"))


@app.route("/admin/product/<int:pid>/delete", methods=["POST"])
@admin_required
def admin_delete_product(pid):
    db = database.get_db()
    db.execute("DELETE FROM product WHERE id = ?", (pid,))
    db.commit()
    flash("상품을 삭제했습니다.")
    return redirect(url_for("admin_index"))










@socketio.on("join_dm")
def on_join_dm(data):
    with app.app_context():
        uid = session.get("user_id")
    if not uid:
        return
    try:
        other = int(data.get("other", 0))
    except (TypeError, ValueError):
        return
    if other <= 0 or other == uid:
        return
    join_room(dm_room(uid, other))


@socketio.on("send")
def on_send(data):
    uid = session.get("user_id")
    if not uid:
        return

    db = database.get_db()
    me = db.execute("SELECT * FROM user WHERE id = ?", (uid,)).fetchone()
    if me is None or me["is_dormant"]:
        return

    content = (data.get("content") or "").strip()
    if not (1 <= len(content) <= 500):
        return

    raw = data.get("to")
    to = None
    if raw not in (None, "", "null"):
        try:
            to = int(raw)
        except (TypeError, ValueError):
            return
        if to == uid or db.execute(
                "SELECT 1 FROM user WHERE id = ?", (to,)).fetchone() is None:
            return

    db.execute("INSERT INTO message (sender_id, receiver_id, content) "
               "VALUES (?, ?, ?)", (uid, to, content))
    db.commit()

    payload = {"username": me["username"], "content": content}
    if to is None:
        emit("message", payload, broadcast=True)
    else:
        emit("message", payload, to=dm_room(uid, to))

if __name__ == "__main__":
    if not os.path.exists(database.DB_PATH):
        database.init_db(app)
    socketio.run(app, host="0.0.0.0", port=5000,
                 debug=False, allow_unsafe_werkzeug=True)