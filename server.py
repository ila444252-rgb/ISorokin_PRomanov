from contextlib import closing
from pathlib import Path

from flask import Flask, abort, request, jsonify, send_from_directory
import sqlite3
import uuid 
import time
import math
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
ALLOWED_ROLES = ['student', 'teacher', 'dispatcher']
ALLOWED_ALERT_TYPES = ['fire', 'terror', 'drone']
SIGNAL_NEEDED = 21
TEACHER_WEIGHT = 100
ALERT_RADIUS_METERS = 500
PANEL_HISTORY_PAGE_SIZE = 25
SCORE_TOTAL_SQL = "COALESCE(SUM(CASE WHEN students.role = 'teacher' THEN ? ELSE students.trust_weight END), 0)"


@app.get('/admin')
@app.get('/panel')
@app.get('/panel.html')
def dispatcher_panel():
    response = send_from_directory(app.root_path, 'panel.html')
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self' https://unpkg.com; "
        "style-src 'self' https://unpkg.com 'unsafe-inline'; "
        "img-src 'self' data: https://tile.openstreetmap.org; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    return response


@app.get('/panel-assets/<name>')
def dispatcher_assets(name):
    if name not in ('panel.css', 'panel.js'):
        abort(404)
    return send_from_directory(Path(app.root_path) / 'panel_assets', name)


@app.after_request
def prevent_panel_data_caching(response):
    if request.endpoint in {
        'get_alerts', 'get_alert_history', 'get_students',
        'confirm_alert', 'close_alert', 'dismiss_alert',
    }:
        response.headers['Cache-Control'] = 'no-store'
    return response


def auth():
    header = request.headers.get('Authorization')
    if not header or header.startswith('Bearer ')==False:
        return None
    else:
        token = header[7:].strip()
        if not token:
            return None
        else:
            conn = sqlite3.connect('uley.db')
            c = conn.cursor()
            c.execute('SELECT device_id, name, role, school_id FROM students WHERE token = ?', (token,))
            row = c.fetchone()
            conn.close()
            return row

def distance_meters(lat1, lon1, lat2, lon2):
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi/2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda/2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c
 
def generate_uuid_token():
    return uuid.uuid4().hex

def init_db():
    conn = sqlite3.connect('uley.db')
    conn.execute('PRAGMA foreign_keys = ON')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS schools (
            school_id TEXT PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            lat REAL NOT NULL CHECK (lat BETWEEN -90 AND 90),
            lon REAL NOT NULL CHECK (lon BETWEEN -180 AND 180)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS students (
            device_id TEXT PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL
                CHECK (role IN ('student', 'teacher', 'dispatcher')),
            school_id TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            trust_weight INTEGER NOT NULL DEFAULT 1
                CHECK (trust_weight BETWEEN 1 AND 10),
            FOREIGN KEY (school_id) REFERENCES schools(school_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS invites (
            code TEXT PRIMARY KEY NOT NULL,
            school_id TEXT NOT NULL,
            role TEXT NOT NULL
                CHECK (role IN ('student', 'teacher', 'dispatcher')),
            used INTEGER NOT NULL DEFAULT 0
                CHECK (used IN (0, 1)),
            FOREIGN KEY (school_id) REFERENCES schools(school_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY NOT NULL,
            school_id TEXT NOT NULL,
            alert_type TEXT NOT NULL
                CHECK (alert_type IN ('fire', 'terror', 'drone')),
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'confirmed', 'closed', 'expired')),
            created_at INTEGER NOT NULL,
            confirmed_at INTEGER,
            finished_at INTEGER,
            confirmed_by TEXT,
            FOREIGN KEY (school_id) REFERENCES schools(school_id),
            FOREIGN KEY (confirmed_by) REFERENCES students(device_id)
        )
    ''')

    c.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS one_active_alert_per_type
        ON alerts (school_id, alert_type)
        WHERE status IN ('pending', 'confirmed')
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS alert_signals (
            alert_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            sent_at INTEGER NOT NULL,
            PRIMARY KEY (alert_id, device_id),
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id),
            FOREIGN KEY (device_id) REFERENCES students(device_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS locations (
            device_id TEXT PRIMARY KEY NOT NULL,
            lat REAL NOT NULL CHECK (lat BETWEEN -90 AND 90),
            lon REAL NOT NULL CHECK (lon BETWEEN -180 AND 180),
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (device_id) REFERENCES students(device_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS alert_locations (
            alert_id TEXT PRIMARY KEY NOT NULL,
            device_id TEXT NOT NULL,
            lat REAL NOT NULL CHECK (lat BETWEEN -90 AND 90),
            lon REAL NOT NULL CHECK (lon BETWEEN -180 AND 180),
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id),
            FOREIGN KEY (device_id) REFERENCES students(device_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS notified (
            alert_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            notified_at INTEGER NOT NULL,
            PRIMARY KEY (alert_id, device_id),
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id),
            FOREIGN KEY (device_id) REFERENCES students(device_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS push_devices (
            device_id TEXT PRIMARY KEY NOT NULL,
            push_token TEXT UNIQUE NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (device_id) REFERENCES students(device_id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS push_deliveries (
            alert_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at INTEGER NOT NULL,
            delivered_at INTEGER,
            PRIMARY KEY (alert_id, device_id),
            FOREIGN KEY (alert_id, device_id) REFERENCES notified(alert_id, device_id)
        )
    ''')

    conn.commit()
    conn.close()


def calc_score(alert_id, conn=None):
    if conn is None:
        with closing(sqlite3.connect('uley.db')) as connection:
            return calc_score(alert_id, connection)
    return conn.execute(f'''
        SELECT {SCORE_TOTAL_SQL}, COUNT(*)
        FROM alert_signals JOIN students USING (device_id)
        WHERE alert_signals.alert_id = ?
    ''', (TEACHER_WEIGHT, alert_id)).fetchone()

def get_student(device_id):
    conn = sqlite3.connect('uley.db')
    c = conn.cursor()

    c.execute('Select name, role, school_id FROM students WHERE device_id = ?', (device_id,))
    row = c.fetchone()
    conn.close()
    return row

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "ошибка"}), 400
    else:
        device_id=data.get('device_id')
        name=data.get('name')
        code=data.get('code')
        if not device_id or not code:
            return jsonify({"status": "error", "message": "ошибка"}), 400
        else:
            conn = sqlite3.connect('uley.db')
            c = conn.cursor()
            try:
                c.execute('UPDATE invites SET used = 1 WHERE code = ? AND used = 0', (code,))
                if c.rowcount == 0:
                    return jsonify({"status": "error", "message": "ошибка"}), 400
                else:
                    c.execute('Select school_id, role FROM invites WHERE code = ?', (code,))
                    row = c.fetchone()
                    school_id = row [0]
                    role = row[1]
                    token = generate_uuid_token()
                    c.execute(
                        'INSERT INTO students (device_id, name, role, school_id, token) VALUES (?, ?, ?, ?, ?)',
                        (device_id, name, role, school_id, token))
                    conn.commit()
                    return jsonify({"status": "ok", "token": token})
            except sqlite3.IntegrityError:
                return jsonify({"status": "error", "message": "такой device_id уже есть"}), 400
            finally:
                conn.close()

@app.route('/alert', methods=['POST'])
def warning():  
    user = auth()
    if user is None:
        return jsonify({"status": "error", "message": "устройство не зарегистрировано"}), 403
    else:    
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"status": "error", "message": "ошибка"}), 400
        alert_type=data.get('alert_type')
        device_id = user[0]
        role = user[2]
        school_id = user[3]
        if alert_type not in ALLOWED_ALERT_TYPES:
            return jsonify({"status": "error", "message": "неизвестный тип тревоги"}), 400
        if role == "dispatcher":
            return jsonify({"status": "error", "message": "диспетчер не отправляет запросы"}), 403
        conn = sqlite3.connect('uley.db')
        c = conn.cursor() 
        try:
            c.execute('BEGIN IMMEDIATE')            
            c.execute('''
                SELECT alert_id, status
                FROM alerts
                WHERE school_id = ?
                  AND alert_type = ?
                  AND status IN ('pending', 'confirmed')
            ''', (school_id, alert_type))
            active_alert = c.fetchone()
            now = int(time.time())

            if active_alert is None:
                alert_id = uuid.uuid4().hex
                c.execute('''
                    INSERT INTO alerts (alert_id, school_id, alert_type, created_at)
                    VALUES (?, ?, ?, ?)
                ''', (alert_id, school_id, alert_type, now))
            else:
                alert_id = active_alert[0]

            c.execute('''
                INSERT INTO alert_signals (alert_id, device_id, sent_at)
                VALUES (?, ?, ?)
                ON CONFLICT (alert_id, device_id) DO NOTHING
            ''', (alert_id, device_id, now))

            c.execute('''
                SELECT lat, lon FROM locations WHERE device_id = ?
            ''', (device_id,))
            location = c.fetchone()

            if location is not None and (active_alert is None or active_alert[1] == 'pending'):
                lat, lon = location
                c.execute('''
                    INSERT INTO alert_locations (alert_id, device_id, lat, lon, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (alert_id) DO UPDATE SET
                        device_id = excluded.device_id,
                        lat = excluded.lat,
                        lon = excluded.lon,
                        updated_at = excluded.updated_at
                    WHERE ? = 'teacher'
                ''', (alert_id, device_id, lat, lon, now, role))
            score, count = calc_score(alert_id, conn)
            conn.commit()
        finally:
            conn.close()
        confirmed = score >= SIGNAL_NEEDED
        return jsonify({
            "status": "ok",
            "alert_id": alert_id,
            "count": count,
            "confirmed": confirmed,
            "score": score
        })

def select_panel_alerts(conn, school_id, *, history_offset=None):
    is_history = history_offset is not None
    statuses = ('closed', 'expired') if is_history else ('pending', 'confirmed')
    order = 'alerts.finished_at' if is_history else 'alerts.created_at'
    limit = PANEL_HISTORY_PAGE_SIZE + 1 if is_history else -1
    rows = conn.execute(f'''
        SELECT alerts.alert_id, alerts.alert_type, alerts.status AS alert_status,
               alerts.created_at, alerts.confirmed_at, alerts.finished_at,
               dispatcher.name AS confirmed_by_name,
               COALESCE(alert_locations.lat, schools.lat) AS lat,
               COALESCE(alert_locations.lon, schools.lon) AS lon,
               CASE WHEN alert_locations.alert_id IS NULL THEN 'school' ELSE 'phone' END AS source,
               (SELECT COUNT(*) FROM alert_signals WHERE alert_id = alerts.alert_id) AS count,
               (SELECT {SCORE_TOTAL_SQL}
                FROM alert_signals JOIN students USING (device_id)
                WHERE alert_signals.alert_id = alerts.alert_id) AS score,
               (SELECT COUNT(*) FROM notified WHERE alert_id = alerts.alert_id) AS recipient_count
        FROM alerts
        JOIN schools ON schools.school_id = alerts.school_id
        LEFT JOIN alert_locations ON alert_locations.alert_id = alerts.alert_id
        LEFT JOIN students AS dispatcher ON dispatcher.device_id = alerts.confirmed_by
        WHERE alerts.school_id = ? AND alerts.status IN (?, ?)
        ORDER BY {order} DESC, alerts.alert_id DESC
        LIMIT ? OFFSET ?
    ''', (TEACHER_WEIGHT, school_id, *statuses, limit, history_offset or 0))
    alerts = []
    for row in rows:
        alert = dict(row)
        alert['location'] = {key: alert.pop(key) for key in ('lat', 'lon', 'source')}
        alert['confirmed'] = alert['score'] >= SIGNAL_NEEDED
        alerts.append(alert)
    return alerts


@app.get('/alerts')
def get_alerts():
    user = auth()
    if user is None or user[2] != 'dispatcher':
        return jsonify({"status": "error", "message": "нужен действующий токен диспетчера"}), 403

    with closing(sqlite3.connect('uley.db')) as conn:
        conn.row_factory = sqlite3.Row
        school = conn.execute('SELECT name, lat, lon FROM schools WHERE school_id = ?', (user[3],)).fetchone()
        if school is None:
            return jsonify({"status": "error", "message": "школа диспетчера не найдена"}), 403
        alerts = select_panel_alerts(conn, user[3])

    return jsonify({
        "result": {alert['alert_type']: alert for alert in alerts},
        "school_name": school['name'],
        "school_location": {"lat": school['lat'], "lon": school['lon']},
        "dispatcher_name": user[1],
        "signal_threshold": SIGNAL_NEEDED,
        "radius_meters": ALERT_RADIUS_METERS,
    })


@app.get('/alerts/history')
def get_alert_history():
    user = auth()
    if user is None or user[2] != 'dispatcher':
        return jsonify({"status": "error", "message": "нужен действующий токен диспетчера"}), 403

    page = request.args.get('page', type=int) if 'page' in request.args else 1
    if page is None or not 1 <= page <= 1_000_000:
        return jsonify({"status": "error", "message": "некорректный номер страницы"}), 400

    with closing(sqlite3.connect('uley.db')) as conn:
        conn.row_factory = sqlite3.Row
        alerts = select_panel_alerts(conn, user[3], history_offset=(page - 1) * PANEL_HISTORY_PAGE_SIZE)

    return jsonify({
        "alerts": alerts[:PANEL_HISTORY_PAGE_SIZE],
        "has_next": len(alerts) > PANEL_HISTORY_PAGE_SIZE,
    })


@app.route('/students', methods=['GET'])
def get_students():
    user = auth()
    if user is None:
        return jsonify({"status": "error", "message": "устройство не зарегистрировано"}), 403
    school_id = user[3]
    if user[2] != "dispatcher":
        return jsonify({"status": "error", "message": "вы не диспетчер"}), 403
    conn = sqlite3.connect('uley.db')
    c = conn.cursor()
    c.execute(
        'SELECT device_id, name, role, school_id, trust_weight FROM students WHERE school_id = ?', (school_id,)
    )
    rows = c.fetchall()
    conn.close()

    result = {}
    for row in rows:
        result[row[0]] = {'name': row[1], 'role': row[2], 'school_id': row[3], 'trust_weight': row[4]}
    return jsonify(result)
@app.route('/trust', methods=['POST'])
def set_trust():
    user = auth()
    if user is None:
        return jsonify({"status": "error", "message": "устройство не зарегистировано"}), 401
    role = user[2]
    if role != "teacher":
            return jsonify({"status": "error", "message": "вы не учитель"}), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "ошибка"}), 403
    student_id = data.get('device_id')
    weight = data.get('weight')
    if not isinstance(weight, int) or weight>=11 or weight <=0:
        return jsonify({"status": "error", "message": "ошибка"}), 403
    
    conn = sqlite3.connect('uley.db')
    c = conn.cursor()
    try:
        c.execute('''
            SELECT role, school_id FROM students WHERE device_id = ?''', (student_id,)
        )
        rows = c.fetchone()
        if rows is None or rows[0]!='student' or user[3]!=rows[1]:
            return jsonify({"status": "error", "message": "ошибка"}), 403
        c.execute('''
        UPDATE students SET trust_weight = ? WHERE device_id = ?''', (weight, student_id))
        conn.commit()
        return jsonify({"status": "ok"})
    finally:
        conn.close()

@app.route('/location', methods=['POST'])
def set_location():
    user = auth()
    if user is None:
        return jsonify({"status": "error", "message": "устройство не зарегистрировано"}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "ошибка"}), 400
    lat = data.get('lat')
    lon = data.get('lon')
    if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)) or isinstance(lat, bool) or isinstance(lon, bool):
        return jsonify({"status": "error", "message": "ошибка"}), 400
    if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
        return jsonify({"status": "error", "message": "ошибка"}), 400
    conn = sqlite3.connect('uley.db')
    c = conn.cursor()
    try:
        c.execute('''
        INSERT OR REPLACE INTO locations (device_id, lat, lon, updated_at) VALUES (?, ?, ?, ?)''', (user[0],lat, lon, int(time.time())))
        conn.commit()
        return jsonify({"status": "ok"})
    finally:
        conn.close()

@app.route('/confirm', methods=['POST'])
def confirm_alert():
    user = auth()
    if user is None or user[2] != 'dispatcher':
        return jsonify({"status": "error", "message": "вы не диспетчер"}), 403

    data = request.get_json(silent=True)
    alert_id = data.get('alert_id') if isinstance(data, dict) else None
    if not isinstance(alert_id, str) or not alert_id.strip():
        return jsonify({"status": "error", "message": "укажите alert_id"}), 400

    device_id, _, _, school_id = user
    conn = sqlite3.connect('uley.db')
    try:
        conn.execute('PRAGMA foreign_keys = ON')
        conn.execute('BEGIN IMMEDIATE')
        c = conn.cursor()
        c.execute('''
            SELECT alerts.status,
                   COALESCE(alert_locations.lat, schools.lat),
                   COALESCE(alert_locations.lon, schools.lon)
            FROM alerts
            JOIN schools ON schools.school_id = alerts.school_id
            LEFT JOIN alert_locations ON alert_locations.alert_id = alerts.alert_id
            WHERE alerts.alert_id = ? AND alerts.school_id = ?
        ''', (alert_id, school_id))
        alert = c.fetchone()
        if alert is None:
            return jsonify({"status": "error", "message": "тревога не найдена"}), 404

        alert_status, alert_lat, alert_lon = alert
        if alert_status == 'pending':
            score, _ = calc_score(alert_id, conn)
            if score < SIGNAL_NEEDED:
                return jsonify({"status": "error", "message": "недостаточно баллов"}), 409

            now = int(time.time())
            c.execute('''
                UPDATE alerts
                SET status = 'confirmed', confirmed_at = ?, confirmed_by = ?
                WHERE alert_id = ?
            ''', (now, device_id, alert_id))

            c.execute('''
                SELECT locations.device_id, locations.lat, locations.lon
                FROM locations
                JOIN students ON students.device_id = locations.device_id
                WHERE students.school_id = ? AND students.role = 'student'
            ''', (school_id,))
            for student_id, lat, lon in c.fetchall():
                if distance_meters(alert_lat, alert_lon, lat, lon) <= ALERT_RADIUS_METERS:
                    c.execute('''
                        INSERT INTO notified (alert_id, device_id, notified_at)
                        VALUES (?, ?, ?)
                    ''', (alert_id, student_id, now))
        elif alert_status != 'confirmed':
            return jsonify({"status": "error", "message": "тревога уже завершена"}), 409

        c.execute('SELECT device_id FROM notified WHERE alert_id = ? ORDER BY device_id', (alert_id,))
        notified = [row[0] for row in c.fetchall()]
        conn.commit()
        return jsonify({"status": "ok", "alert_id": alert_id, "notified": notified})
    finally:
        conn.close()


@app.route('/close', methods=['POST'])
def close_alert():
    return finish_alert('confirmed', 'closed', 'закрыть можно только подтверждённую тревогу')


@app.post('/dismiss')
def dismiss_alert():
    return finish_alert('pending', 'expired', 'отклонить можно только неподтверждённую тревогу')


def finish_alert(expected_status, finished_status, invalid_message):
    user = auth()
    if user is None or user[2] != 'dispatcher':
        return jsonify({"status": "error", "message": "вы не диспетчер"}), 403

    data = request.get_json(silent=True)
    alert_id = data.get('alert_id') if isinstance(data, dict) else None
    if not isinstance(alert_id, str) or not alert_id.strip():
        return jsonify({"status": "error", "message": "укажите alert_id"}), 400

    conn = sqlite3.connect('uley.db')
    try:
        conn.execute('BEGIN IMMEDIATE')
        alert = conn.execute('''
            SELECT status FROM alerts WHERE alert_id = ? AND school_id = ?
        ''', (alert_id, user[3])).fetchone()
        if alert is None:
            return jsonify({"status": "error", "message": "тревога не найдена"}), 404

        alert_status = alert[0]
        if alert_status == expected_status:
            conn.execute('''
                UPDATE alerts SET status = ?, finished_at = ?
                WHERE alert_id = ?
            ''', (finished_status, int(time.time()), alert_id))
        elif alert_status != finished_status:
            return jsonify({"status": "error", "message": invalid_message}), 409

        conn.commit()
        return jsonify({"status": "ok", "alert_id": alert_id, "alert_status": finished_status})
    finally:
        conn.close()


@app.route('/push-token', methods=['PUT'])
def set_push_token():
    user = auth()
    if user is None:
        return jsonify({"status": "error", "message": "устройство не зарегистрировано"}), 401
    if user[2] == 'dispatcher':
        return jsonify({"status": "error", "message": "push недоступен для диспетчера"}), 403

    data = request.get_json(silent=True)
    token = data.get('token') if isinstance(data, dict) else None
    if not isinstance(token, str) or not 16 <= len(token) <= 4096 or not token.isascii() or not token.isprintable() or any(char.isspace() for char in token):
        return jsonify({"status": "error", "message": "некорректный push-токен"}), 400

    device_id = user[0]
    conn = sqlite3.connect('uley.db')
    try:
        conn.execute('PRAGMA foreign_keys = ON')
        with conn:
            conn.execute('DELETE FROM push_devices WHERE push_token = ? AND device_id != ?', (token, device_id))
            conn.execute('''
                INSERT INTO push_devices (device_id, push_token, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT (device_id) DO UPDATE SET
                    push_token = excluded.push_token, updated_at = excluded.updated_at
            ''', (device_id, token, int(time.time())))
        return jsonify({"status": "ok"})
    finally:
        conn.close()


@app.route('/notifications', methods = ['GET'])
def alert_request():
    user = auth()
    if user is None:
        return jsonify({"status": "error", "message": "ошибка"}), 401
    device_id = user[0]
    conn = sqlite3.connect('uley.db')
    try:
        rows = conn.execute('''
            SELECT alerts.alert_type
            FROM notified
            JOIN alerts ON alerts.alert_id = notified.alert_id
            WHERE notified.device_id = ? AND alerts.status = 'confirmed'
            ORDER BY notified.notified_at DESC, alerts.alert_id
        ''', (device_id,)).fetchall()
    finally:
        conn.close()

    return jsonify({"status": "ok", "alerts": [row[0] for row in rows]})


if __name__ == '__main__':
    init_db()
    app.run()
