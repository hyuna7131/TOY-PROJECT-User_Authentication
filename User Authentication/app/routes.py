from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import db, bcrypt
from app.models import User, Post

main = Blueprint('main', __name__)

@main.route("/")
def noticeboard():
    posts = Post.query.all()
    token = request.cookies.get('access_token')
    logged_in = False
    username = None
    if token:
        try:
            identity = get_jwt_identity()  # 사용자 ID를 가져옵니다.
            user = User.query.get(identity)  # 사용자 정보를 데이터베이스에서 조회합니다.
            if user:
                logged_in = True
                username = user.username  # 사용자 이름을 가져옵니다.
        except Exception:
            logged_in = False
    return render_template('noticeboard.html', posts=posts, logged_in=logged_in, username=username)



@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            response = redirect(url_for('main.home'))
            response.set_cookie('access_token', access_token, httponly=True)
            flash('Logged in successfully!', 'success')
            return response
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html')

@main.route('/logout')
@jwt_required()
def logout():
    response = redirect(url_for('main.home'))
    response.delete_cookie('access_token')
    flash('You have been logged out.', 'info')
    return response

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully!', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/new_post', methods=['GET', 'POST'])
@jwt_required()
def new_post():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        user_id = get_jwt_identity()
        post = Post(title=title, content=content, user_id=user_id)
        db.session.add(post)
        db.session.commit()
        flash('Post created successfully!', 'success')
        return redirect(url_for('main.home'))
    return render_template('post_create.html')

@main.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', post=post)

@main.route('/search', methods=['GET'])
def search():
    search_type = request.args.get('type')
    keyword = request.args.get('keyword')

    if search_type == 'title':
        posts = Post.query.filter(Post.title.like(f'%{keyword}%')).all()
    elif search_type == 'content':
        posts = Post.query.filter(Post.content.like(f'%{keyword}%')).all()
    else:
        posts = []

    return render_template('post_search.html', posts=posts, keyword=keyword)