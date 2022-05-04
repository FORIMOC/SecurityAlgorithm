from flask import Flask, render_template, request
import json
import random
import functools
PRIME = 2 ** 31 - 1
RINT_FUNC = functools.partial(random.SystemRandom().randint, 0)
app = Flask(__name__)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/generate', methods=['POST'])
def generator():
    def value_at(poly, x, p):
        value = 0
        for i in range(len(poly)):
            value += poly[i] * x ** i
        return value % p

    def make_random_shares(t, n, p=PRIME):
        if t > n:
            raise ValueError("门限不能大于密钥总数!")
        poly = [RINT_FUNC(p - 1) for i in range(t)]
        points = [(i, value_at(poly, i, p)) for i in range(1, n + 1)]
        return poly[0], points

    if request.method == 'POST':
        t = int(request.values.get('t'))
        n = int(request.values.get('n'))
        if t > n:
            resp = {
                'code': 422,
                'msg': "门限不能大于密钥总数!"
            }
            return json.dumps(resp)
        secret, points = make_random_shares(t, n, PRIME)
        resp = {
            'code': 200,
            'secret': secret,
            'points': points
        }
        return json.dumps(resp)


@app.route('/decrypt', methods=['POST'])
def decryptor():
    def egcd(a, b):
        if b == 0:
            return a, 1, 0
        r, x, y = egcd(b, a % b)
        return r, y, x - a // b * y

    def lagrange_interpolate(selected_points, p):
        s = 0
        for i in range(len(selected_points)):
            up = 1
            down = 1
            for j in range(len(selected_points)):
                if i != j:
                    up *= -selected_points[j][0]
                    down *= selected_points[i][0] - selected_points[j][0]
            item = (up * egcd(down, p)[1]) % p
            s += item * selected_points[i][1]
        return s % p

    if request.method == 'POST':
        data = request.get_data()
        data = json.loads(data)
        points = data.get('points')
        for point in points:
            point[1] = int(point[1])
        secret = lagrange_interpolate(points, PRIME)
        resp = {
            'code': 200,
            "decrypted_secret": secret
        }
        return json.dumps(resp)


if __name__ == '__main__':
    app.run(host="0.0.0.0")
