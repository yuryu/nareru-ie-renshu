#import MySQLdb
#from MySQLdb.cursors import DictCursor
import pymysql.cursors
import pymysql
import redis

from flask import (
    Flask, request, redirect, session, url_for, flash, jsonify,
    render_template, _app_ctx_stack
)
import flask
import datetime

from werkzeug.contrib.fixers import ProxyFix

import os, hashlib
from datetime import date

config = {}
user_dic = {}
app = Flask(__name__, static_url_path='')
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = os.environ.get('ISU4_SESSION_SECRET', 'shirokane')

def load_config():
    global config
    config = {
         'user_lock_threshold': int(os.environ.get('ISU4_USER_LOCK_THRESHOLD', 3)),
         'ip_ban_threshold': int(os.environ.get('ISU4_IP_BAN_THRESHOLD', 10))
    }
    return config

def load_users():
    global user_dic
    f = open('/home/isucon/sql/dummy_users.tsv', 'r')
    for line in f:
        a = line.rstrip().split('\t')
        user = {'id': a[0], 'login': a[1], 'password': a[2], 'salt': a[3], 
                'password_hash': a[4]}
        user_dic[a[1]] = user
    f.close()
    print(user_dic)

def user_fail_key(user):
    return "user_fail_" + user

def ip_fail_key(ip):
    return "ip_fail_" + ip 

def user_lastlogin_key(user):
    return "user_lastlogin_" + user

def user_lastlogin_ip_key(user):
    return "user_lastlogin_ip_" + user

def redis_get_int(r, key):
    v = r.get(key)
    if v is None:
        return 0
    return int(v)

def connect_db():
    host = os.environ.get('ISU4_DB_HOST', 'localhost')
    port = int(os.environ.get('ISU4_DB_PORT', '3306'))
    dbname = os.environ.get('ISU4_DB_NAME', 'isu4_qualifier')
    username = os.environ.get('ISU4_DB_USER', 'root')
    password = os.environ.get('ISU4_DB_PASSWORD', '')
    db = pymysql.connect(host=host, port=port, db=dbname, user=username, passwd=password, cursorclass=pymysql.cursors.DictCursor, charset='utf8')
    return db

def get_redis():
    if not hasattr(flask.g, 'redis'):
        flask.g.redis = redis.Redis()
    return flask.g.redis

def get_db():
    if not hasattr(flask.g, 'database'):
        flask.g.database = connect_db()
    return flask.g.database

def calculate_password_hash(password, salt):
    return hashlib.sha256((password + ':' + salt).encode('utf-8')).hexdigest()

def login_log(succeeded, login, user_id=None):
    print('login_log: ' + str(succeeded) + ', ' + login + ', ' + str(user_id))
    r = get_redis()
    ip = request.remote_addr
    if succeeded:
        p = r.pipeline()
        p.set(user_fail_key(user_id), 0)
        p.set(ip_fail_key(ip), 0)
        p.lpush(user_lastlogin_key(user_id), datetime.datetime.now().timestamp())
        p.lpush(user_lastlogin_ip_key(user_id), ip)
        p.execute()
    else:
        p = r.pipeline()
        p.incr(ip_fail_key(ip))
        if user_id is not None:
            p.incr(user_fail_key(user_id))
        p.execute()

def user_locked(user):
    if not user:
        return None
    r = get_redis()
    cnt = redis_get_int(r, user_fail_key(user['login']))
    print(cnt);
    print("user_locked: cnt = %s, config = %d" % (cnt, config['user_lock_threshold']))
    return config['user_lock_threshold'] <= cnt

def ip_banned():
    r = get_redis()
    cnt = redis_get_int(r, ip_fail_key(request.remote_addr))
    print(cnt);
    print("ip_banned: cnt = %s, config = %d" % (cnt, config['ip_ban_threshold']))
    return config['ip_ban_threshold'] <= cnt

def attempt_login(login, password):
    user = user_dic.get(login)
#    cur = get_db().cursor()
#    cur.execute('SELECT * FROM users WHERE login=%s', (login,))
#    user = cur.fetchone()
#    cur.close()

    if ip_banned():
        if user:
            login_log(False, login, user['login'])
        else:
            login_log(False, login)
        return [None, 'banned']

    if user_locked(user):
        login_log(False, login, user['login'])
        return [None, 'locked']

    if user and calculate_password_hash(password, user['salt']) == user['password_hash']:
        login_log(True, login, user['login'])
        return [user, None]
    elif user:
        login_log(False, login, user['login'])
        return [None, 'wrong_password']
    else:
        login_log(False, login)
        return [None, 'wrong_login']

def current_user():
    if not session['login']:
        return None
    return user_dic.get(session['login'])
#    cur = get_db().cursor()
#    cur.execute('SELECT * FROM users WHERE id=%s', (session['user_id'],))
#    user = cur.fetchone()
#    cur.close()
#    if user:
#        return user
#    else:
#        return None

def last_login():
    user = current_user()
    if not user:
        return None

    r = get_redis()
    lastlogins = r.lrange(user_lastlogin_key(user['login']), 0, 1)
    lastlogins_ip = r.lrange(user_lastlogin_ip_key(user['login']), 0, 1)

    return {"datetime": datetime.datetime.fromtimestamp(float(lastlogins[-1])), 
            "ip": lastlogins_ip[-1].decode('utf-8')}

def banned_ips():
    threshold = config['ip_ban_threshold']
    r = get_redis()
    ips = []
    start = len("ip_fail_")
    for ipkey in r.scan_iter("ip_fail_*"):
        if redis_get_int(r, ipkey) >= threshold:
            print(ipkey)
            ip = ipkey.decode("utf-8")
            ips.append(ip[start:])
    return ips

def locked_users():
    threshold = config['user_lock_threshold']
    r = get_redis()
    users = []
    start = len("user_fail_")
    for userkey in r.scan_iter("user_fail_*"):
        if redis_get_int(r, userkey) >= threshold:
            user = userkey.decode("utf-8")
            users.append(user[start:])
    return users

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    login = request.form['login']
    password = request.form['password']
    user, err = attempt_login(login, password)
    if user:
        session['login'] = user['login']
        return redirect(url_for('mypage'))
    else:
        print('err = ' + err)
        if err == 'locked':
            flash('This account is locked.')
        elif err == 'banned':
            flash("You're banned.")
        else:
            flash('Wrong username or password')
        return redirect(url_for('index'))

@app.route('/mypage')
def mypage():
    user = current_user()
    if user:
        return render_template('mypage.html', user=user, last_login=last_login())
    else:
        flash('You must be logged in')
        return redirect(url_for('index'))

@app.route('/report')
def report():
    response = jsonify({ 'banned_ips': banned_ips(), 'locked_users': locked_users() })
    response.status_code = 200
    return response

if __name__ == '__main__':
    load_config()
    load_users()
    port = int(os.environ.get('PORT', '5000'))
    app.run(debug=1, host='0.0.0.0', port=port)
else:
    load_config()
    load_users()
