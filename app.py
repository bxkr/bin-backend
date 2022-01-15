import shutil
import sqlite3

from flask import Flask, g, request

app = Flask(__name__)
FLASK_RESPONSE = tuple[dict[str, str], int]


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(__file__.replace('app.py', 'bins.db'))
    return db


def get_username(password: str) -> str | None:
    conn = sqlite3.connect(__file__.replace('app.py', 'auth.db'))
    cur = conn.cursor()
    cur.execute('select uid from passwords where password = ?', [password])
    result = cur.fetchall()
    if result:
        cur.execute('select username from users where ROWID = ?', [result[0][0]])
        result = cur.fetchall()
        if result:
            return result[0][0]
    conn.close()


def register(username: str, password: str) -> FLASK_RESPONSE:
    conn = sqlite3.connect(__file__.replace('app.py', 'auth.db'))
    cur = conn.cursor()
    cur.execute('select * from users where username = ?', [username])
    if cur.fetchall():
        conn.close()
        return {'error': 'user with this username already exists!'}, 400
    else:
        cur.execute('insert into users values (?)', [username])
        cur.execute('select ROWID from users where username = ?', [username])
        cur.execute('insert into passwords values (?, ?)', [password, cur.fetchall()[0][0]])
        conn.commit()
        conn.close()
        return {'status': f'user {username} created successfully!'}, 201


def change_password(username: str, old: str, new: str) -> FLASK_RESPONSE:
    conn = sqlite3.connect(__file__.replace('app.py', 'auth'))
    cur = conn.cursor()
    cur.execute('select ROWID from users where username = ?', [username])
    uid_table = cur.fetchall()
    if uid_table:
        cur.execute('select uid from passwords where password = ? and uid = ?', [old, uid_table[0][0]])
        if cur.fetchall():
            cur.execute('update passwords set password = ? where password = ? and uid = ?', [new, old, uid_table[0][0]])
            conn.commit()
            conn.close()
            return {'status': 'password changed successfully!'}, 200
        else:
            conn.close()
            return {'error': 'provided password is not correct!'}, 400
    else:
        conn.close()
        return {'error': 'user with this username does not exists!'}, 400


@app.teardown_appcontext
def close_connection(e):
    if e:
        pass
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.get('/')
def disk_usage():
    return {'free_bytes': shutil.disk_usage(__file__)[2]}


@app.get('/get/<string:slug>')
def get_bin_raw(slug: str):
    cur = get_db().cursor()
    cur.execute('select content, author from bins where slug = ?', [slug])
    try:
        result = cur.fetchall()[0]
        return {'text': result[0], 'author': result[1]}
    except IndexError:
        return {'error': 'bin does not exist'}, 404


@app.post('/post/<string:slug>')
def insert_bin_raw(slug: str):
    author = None
    if 'token' in request.args:
        author = get_username(request.args['token'])
    if author is None:
        author = request.remote_addr
    allowed = True
    cur = get_db().cursor()
    cur.execute('select * from bins where slug = ?', [slug])
    current_bin = cur.fetchall()
    overwriting = False
    if current_bin:
        overwriting = True
        allowed = current_bin[0][2] == author
    if allowed:
        cur.execute('insert or replace into bins values (?, ?, ?)', [slug, request.data.decode('utf-8'), author])
        get_db().commit()
        return {'status': ('overwrote' if overwriting else 'created') + ' successfully!'}, 201
    else:
        return {'error': 'you tried to overwrite a bin that does not belong to you!'}, 403


@app.route('/register')
def register_route():
    if not ('username' in request.args and 'password' in request.args):
        return {'manual_request': 'username and password required!'}, 400
    if len(request.args['password']) != 40:
        return {'manual_request': 'your password hash is not formatted correctly (need sha1)!'}, 400
    if not (4 <= len(request.args['username']) <= 64):
        print(request.args['username'])
        return {'manual_request': 'your username is not formatted correctly (need 4 <= length <= 64)!'}, 400
    return register(request.args['username'], request.args['password'])


@app.route('/change_password')
def change_password_route():
    if not ('username' in request.args and 'old_password' in request.args and 'new_password' in request.args):
        return {'manual_request': 'username, old and new passwords required!'}, 400
    if len(request.args['new_password']) != 40:
        return {'manual_request': 'your password hash is not formatted correctly (need sha1)!'}, 400
    return change_password(request.args['username'], request.args['old_password'], request.args['new_password'])


if __name__ == '__main__':
    app.run()
