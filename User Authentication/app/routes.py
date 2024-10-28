from flask import Blueprint, render_template, redirect, url_for, request, flash, session, make_response
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, set_access_cookies, set_refresh_cookies, unset_jwt_cookies, exceptions
from jwt.exceptions import ExpiredSignatureError

from app import db, bcrypt, jwt
from app.models import User, Post

main = Blueprint('main', __name__)

@main.route("/")
@jwt_required(optional=True)
def noticeboard():
    posts = Post.query.all()
    token = request.cookies.get('access_token_cookie')
    logged_in = False
    firstname = None
    if token:
        try:
            identity = get_jwt_identity()  # 사용자 ID를 가져옵니다.
            if identity:
                user = User.query.get(identity)  # 사용자 정보를 데이터베이스에서 조회합니다.
                if user:
                    logged_in = True
                    firstname = user.firstname  # 사용자 이름을 가져옵니다.
        except Exception as e:
            print(f"Error getting user identity: {e}")  # 예외 로그 출력
    return render_template('noticeboard.html', posts=posts, logged_in=logged_in, firstname=firstname)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        id = request.form.get('id') 
        password = request.form.get('password')
        user = User.query.filter_by(id=id).first()

        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id)
            # response = redirect(url_for('main.noticeboard'))
            # response.set_cookie('access_token', access_token, httponly=True, samesite='Lax')
            # response.set_cookie('refresh_token', refresh_token, httponly=True, samesite='Lax')
            flash('Logged in successfully!', 'success')
            # return response

            resp = make_response(redirect(url_for('main.noticeboard')))
            set_access_cookies(resp, access_token)
            set_refresh_cookies(resp, refresh_token)
            return resp

        else:
            flash('Login failed. Check your ID and Password.', 'danger')
    return render_template('login.html')

@main.route('/logout')
def logout():
    #response = redirect(url_for('main.noticeboard'))
    #response.delete_cookie('access_token')
    #flash('You have been logged out.', 'info')
    #return response
    response = {"status": "success", "msg": "로그아웃", "redirect_url": "main.login"}
    resp = make_response(render_template('/login.html', response=response))
    unset_jwt_cookies(resp)
    return resp

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        id = request.form.get('id')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        email = request.form.get('email')
        school = request.form.get('school')
        address = request.form.get('address')

        user = User(id=id, firstname=firstname, lastname=lastname, password=hashed_password, email=email, school=school, address=address)
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully!', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/post_create', methods=['GET', 'POST'])
@jwt_required()
def post_create():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        secret = request.form.get('secret') == 'on'
        secret_password = request.form.get('secret_password')
        user_id = get_jwt_identity()

        post = Post(title=title, content=content, secret=secret, secret_password=secret_password, user_id=user_id)
        db.session.add(post)
        db.session.commit()
        flash('Post created successfully!', 'success')
        return redirect(url_for('main.noticeboard'))
    return render_template('post_create.html')

@main.route('/post/<int:index>', methods=['GET', 'POST'])
def post(index):
    post = Post.query.get_or_404(index) 
    if post.secret:  # 비밀글인지 확인합니다.
        if request.method == 'POST':
            input_password = request.form.get('password')
            # 비밀글의 비밀번호를 확인합니다.
            if bcrypt.check_password_hash(post.secret_password, input_password):
                session[f'post_{index}_access'] = True  # 세션에 접근 권한을 저장합니다.
                #return render_template('post.html', post=post, index=index)
                return redirect(url_for('main.post', index=index))
            else:
                flash('Incorrect password. Please try again.', 'danger')

    # 비밀글이 아니거나 비밀번호가 올바른 경우 게시글을 표시합니다.
    return render_template('post.html', post=post, index=index)

@main.route('/post_edit', methods=['POST'])
def edit():
    return 1


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



@main.route('/token/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()  # 현재 사용자 ID 가져오기
    new_access_token = create_access_token(identity=current_user)
    response = {"access_token": new_access_token}
    return response, 200

@jwt.user_lookup_loader
def load_user_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]  # 여기서 identity는 문자열입니다.
    user = User.query.get(identity)  # 문자열로 조회
    #print(f"Loaded user: {user}")  # 사용자 조회 확인
    return user


# 인증 실패 시 로그인 페이지로 이동
@main.errorhandler(exceptions.NoAuthorizationError)
def handle_auth_error(e):
    response = {"status": "warning", "msg": "로그인이 필요한 페이지 입니다.", "redirect_url": "/login"}
    return render_template('/login.html', response=response)

# 중복된 토큰 사용 시 로그인 페이지로 이동
# NOTE: 일반적인 경우 중복된 토큰을 사용할 수 없음 -> 토큰 삭제 
#        - ex) 만료되기 이전에 로그아웃을 한 뒤, 해당 토큰을 또 재사용한 경우
@main.errorhandler(exceptions.RevokedTokenError)
def handle_auth_error(e):
    response = {"status": "warning", "msg": "비정상적인 요청을 하셨습니다.\\n로그인을 다시 해주세요.", "redirect_url": "/login"}
    resp = make_response(render_template('/login.html', response=response))
    unset_jwt_cookies(resp)
    return resp

# Refresh Token 만료 시 로그인 페이지로 이동
# NOTE: Access Token은 매 라우팅 요청 시마다 갱신됨 단, @jwt_rquired() 데코레이터가 있는 경우만
@main.errorhandler(ExpiredSignatureError)
def handle_token_expired(e):
    response = {"status": "warning", "msg": "로그인 세션 만료\\n로그인을 다시 해주세요.", "redirect_url": "/login"}
    resp = make_response(render_template('/login.html', response=response))
    unset_jwt_cookies(resp)
    return resp