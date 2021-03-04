from flask import Flask, render_template, url_for, request, redirect, session, g, abort

from models.bruteForce import directory_brute_force, files_brute_force
from models.scanHeaders import HeadersRaw, missing_headers, evaluate_information_disclosure

from models.scanHeaders import HeadersRaw

app = Flask(__name__)


@app.route('/', methods=["POST", "GET"])
def index():
    return render_template('home.html')


@app.route('/homepage', methods=["POST", "GET"])
def homepage():
    return render_template('home.html')


@app.route('/headers', methods=["POST", "GET"])
def headers():
    header = HeadersRaw()
    # If we have input url we will check security headers, which headers are missing
    if request.method == 'POST':
        input_url = request.values['key']
        if input_url:
            result_headers = header.raw_headers(input_url)
            missing = missing_headers(result_headers)
            evaluate = evaluate_information_disclosure(result_headers)
            return render_template('informationDisclosure.html', result=result_headers, missing=missing,
                                   evaluate=evaluate)
        else:
            return render_template('informationDisclosure.html')
    return render_template('informationDisclosure.html')


@app.route('/brute_force', methods=["POST", "GET"])
def brute_force():
    # If we have input url we will check brute force directory and brute force files
    if request.method == 'POST':
        input_url = request.values['key']
        if input_url:
            result_directory = directory_brute_force(input_url)
            result_files = files_brute_force(input_url)
            return render_template('directoryFilesBruteForce.html', result=result_directory, result2=result_files)
        else:
            return render_template('directoryFilesBruteForce.html')

    return render_template('directoryFilesBruteForce.html')


@app.route('/sql_injection', methods=["POST", "GET"])
def sql():
    if request.method == 'POST':
        input_url = request.values['key']

    return render_template('sqlInjection.html')


if __name__ == "__main__":
    app.run()
