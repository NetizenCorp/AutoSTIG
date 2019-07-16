import os
import pprint
import json

#Custom Libraries
import stig_lib
import database_lib

from flask import Flask, render_template, jsonify, url_for, request

template_folder = "templates"
static_folder = "static"
application_path = os.path.dirname(__file__)
app = Flask(__name__, template_folder = template_folder, static_folder = static_folder)

@app.route('/')
def blnak_page(name=None):
    stig_status = stig_lib.stig_data().get_stig_status() 
    #print (stig_status)
    return render_template('section1.html', stig_status=stig_status)

@app.route('/stig/process')
def stig_process():
    sqlite_db = database_lib.Database().Sqlite()
    application_path = os.path.dirname(__file__)
    stig_lib.stig_data().run_stig(sqlite_db, application_path + '/STIGs')
    sqlite_db.sqlite_close()
    stig_status = stig_lib.stig_data().get_stig_status()
    return jsonify(stig_status)

@app.route('/stig/<name>')
def get_stig(name):
    sqlite_db = database_lib.Database().Sqlite()
    application_path = os.path.dirname(__file__)

    stig_info_result = stig_lib.stig_data().get_stig_info(sqlite_db, application_path + '/STIGs', name)
    profile_info_result = stig_lib.stig_data().get_profile_info(sqlite_db, application_path + '/STIGs', name)
    sqlite_db.sqlite_close()

    return jsonify({'stig':stig_info_result, 'profile':profile_info_result})

@app.route('/stig/vuln/<name>')
def get_vuln(name):
    # HACK TEST KtQ
    print("/stig/vuln/<name>")
    sqlite_db = database_lib.Database().Sqlite()
    application_path = os.path.dirname(__file__)

    #stig_info_result = stig_lib.stig_data().get_stig_info(sqlite_db, application_path + '/STIGs', name)
    #profile_info_result = stig_lib.stig_data().get_profile_info(sqlite_db, application_path + '/STIGs', name)
    vuln = stig_lib.stig_data().get_single_vuln(sqlite_db, application_path + '/STIGs', name)
    sqlite_db.sqlite_close()
    print("here")
    print(jsonify(vuln))
    return jsonify({'vuln':vuln})

@app.route('/stig/run', methods=['GET', "POST"])
def run_stig():
    # HACK TEST KtQ
    sqlite_db = database_lib.Database().Sqlite()
    application_path = os.path.dirname(__file__)

    STIG_VULNS = stig_lib.stig_data().get_profile_vulns(sqlite_db, application_path + '/STIGs', request.json["STIG_selected"])
    #bontent = jsonify(STIG_VULNS)
    #data = json.loads(request.json)
    pibber = request.json["STIG_selected"]
    content = STIG_VULNS
    print ("Content= " + str(pibber))
    return render_template('section2.html', content=content)


@app.route('/stig/report')
def stig_report():
    return render_template('section3.html')


if __name__ ==  "__main__":
    app.run(debug=True, host="0.0.0.0",port=5000)