## 설치 및 실행 방법

### 1. 저장소 복제

```bash
git clone https://github.com/<your-id>/secure-coding
cd secure-coding
```

### 2. 가상환경 생성 및 활성화

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. 패키지 설치

```bash
pip install flask flask-socketio eventlet flask-wtf flask-limiter argon2-cffi
```

### 4. 실행

```bash
python3 app.py
```

`market.db`가 없으면 `schema.sql`을 기반으로 자동 생성됩니다.

### 5. 접속

브라우저에서 아래 주소로 접속합니다.
http://localhost:5000/


## 관리자 계정 설정

관리자 승격은 보안상 웹에서 제공할 수 없습니다. 웹에서 회원가입한 뒤 아래 명령으로 설정합니다.

```bash
python3 -c "
import sqlite3
c = sqlite3.connect('market.db')
c.execute(\"UPDATE user SET is_admin = 1 WHERE username = 'admin'\")
c.commit()
print('변경:', c.total_changes)
"
```

`변경: 1`이 출력되면 성공입니다. 로그아웃 후 다시 로그인하면 관리자 메뉴가 표시됩니다.

## 디렉터리 구조
secure-coding/

├── app.py # 라우팅 및 로직

├── db.py # DB 연결 관리

├── schema.sql # 테이블 정의

├── templates/ # Jinja2 템플릿

├── static/uploads/ # 업로드된 상품 이미지

├── .gitignore

└── README.md
