import json
import sqlite3

import bcrypt as bcrypt
import pandas as pd
import matplotlib as mp
from flask import Flask, jsonify, render_template
from flask import request
import requests

###### CONEXIONES Y FICHEROS #########
data = pd.read_csv("Data/alerts.csv")
dev = open("data/devices.json")
devices = json.load(dev)
rows = data.shape[0]
conexion = sqlite3.connect("bd1.db")
cursor = conexion.cursor()

######## CREACIÓN DE TABLAS #############
conexion.execute("""create table if not exists articulos (
                              fecha text,
                              sid integer primary key,
                              msg text,
                              clasification text, 
                              prioridad integer,
                              protocolo text,
                              origen text, 
                              destino text, 
                              puerto integer
                        )""")
conexion.execute("""create table if not exists dispositivos(
                                  id text,
                                  ip text primary key,
                                  localizacion text,
                                  responsable text,
                                  analisis integer
                            )""")
cursor.execute("""create table if not exists responsables(
                                      name text primary key,
                                      telefono integer,
                                      rol text
                                )""")
cursor.execute("""create table if not exists analisis(
                                      id integer,
                                      ip integer,
                                      puertos_abiertos text,
                                      n_puertos_abiertos integer,
                                      servicios integer,
                                      servicios_inseguros integer,
                                      vulnerabilidades_detectadas integer,
                                      primary key(puertos_abiertos, n_puertos_abiertos, servicios, servicios_inseguros, vulnerabilidades_detectadas)
                                )""")

cursor.execute("""create table if not exists users_login(
                                      id integer primary key,
                                      name text unique,
                                      password_hash integer, 
                                      salt text
                                )""")

############## RELLENAR TABLAS #############################

admin = "soyadmin"
paco = "soypaco"
luis = "soyluis"
admiin = "soyadmiin"

salt = bcrypt.gensalt()

admin_pass = bcrypt.hashpw(admin.encode('utf-8'), salt)
conexion.execute("INSERT OR IGNORE INTO users_login (name, password_hash, salt) VALUES(?,?,?)", ("admin", admin_pass, salt))
salt = bcrypt.gensalt()
paco_pass =bcrypt.hashpw(paco.encode('utf-8'), salt)
conexion.execute("INSERT OR IGNORE INTO users_login (name, password_hash, salt) VALUES(?,?,?)", ("Paco Garcia", paco_pass, salt))
salt = bcrypt.gensalt()
luis_pass = bcrypt.hashpw(luis.encode('utf-8'), salt)
conexion.execute("INSERT OR IGNORE INTO users_login (name, password_hash, salt) VALUES(?,?,?)", ("Luis Sanchez", luis_pass, salt))
salt = bcrypt.gensalt()
admiin_pass = bcrypt.hashpw(admiin.encode('utf-8'), salt)

conexion.execute("INSERT OR IGNORE INTO users_login (name, password_hash, salt) VALUES(?,?,?)", ("admiin", admiin_pass, salt))


analisis_id = 0
for a in devices:
        responsable = a['responsable']
        cursor.execute("INSERT OR IGNORE INTO responsables (name,telefono,rol) VALUES(?,?,?)", (responsable['nombre'], responsable['telefono'], responsable['rol']))
        analisis = a['analisis']
        if analisis["puertos_abiertos"] == 'None':
            aux = 0
        else:
            aux = len(analisis["puertos_abiertos"])

        cursor.execute("INSERT OR IGNORE INTO analisis (id, ip, puertos_abiertos, n_puertos_abiertos, servicios, servicios_inseguros, vulnerabilidades_detectadas) VALUES(?,?,?,?,?,?,?)", (analisis_id, a['ip'],json.dumps(analisis['puertos_abiertos']), aux, analisis['servicios'], analisis['servicios_inseguros'], analisis['vulnerabilidades_detectadas']))
        cursor.execute("INSERT OR IGNORE INTO dispositivos (id,ip,localizacion,responsable,analisis) VALUES(?,?,?,?,?)", (a['id'],a['ip'],a['localizacion'],responsable['nombre'],analisis_id))
        ##devices.to_sql("dispositivos", conexion, if_exists="replace", index=False)
        analisis_id+=1

data.to_sql("articulos", conexion, if_exists="replace", index=False)

conexion.close()

def flask():
    app = Flask(__name__)

    @app.route('/')
    def index():
        return '''
            <h1>CMI</h1>
            <a href="/login">LOGIN</a>
            <p>Dispositivos Problemáticos</p>
            <form action="/DispositivosProblematicos" method="POST">
                <input type="number" id="numero" name="numero">
                <button type="submit">ENVIAR</button>
            </form>
            <p>IPs Problemáticas</p>
            <ul></ul>
            <form action="/IPProblematicas" method="POST">
                <input type="number" id="numero2" name="numero2">
                
                <button type="submit">ENVIAR</button>
            </form>
            <ul></ul>
            <p>Dispositivos Peligrosos</p>
            <form action="/DispositivosPeligrosos" method="POST">
                <input type="number" id="numero3" name="numero3">
                <input type="checkbox" name="menosPeligrosos">
                <label for="menosPeligroso">Marca para menos peligrosos</label>
                <button type="submit">ENVIAR</button>
            </form>
            <a href="/CVE">TOP 10 CVEs</a>
            <ul></ul>
        '''
    @app.route('/DispositivosProblematicos', methods=["POST"])
    def DispositivosProblematicos():

        numero = int(request.form['numero'])
        con = sqlite3.connect("bd1.db")
        curs = con.cursor()
        curs.execute("SELECT analisis.vulnerabilidades_detectadas, dispositivos.id FROM dispositivos INNER JOIN analisis ON analisis.id=dispositivos.analisis ORDER BY analisis.vulnerabilidades_detectadas DESC LIMIT {}".format(numero))
        result = curs.fetchall()
        html = f'<h1>Dispositivos más problematicos</h1>'
        html += f'<ul>'
        for a in result:
            html += f'<ul><li>VULNERABILIDADES: {a[0]} <li>ID: {a[1]}</ul>'
        html += f'</ul>'
        con.close()
        return html

    @app.route('/IPProblematicas', methods=["POST"])
    def ipProblematicas():
        numero = int(request.form['numero2'])
        con = sqlite3.connect("bd1.db")
        curs = con.cursor()
        curs.execute(
            "SELECT origen, COUNT(*) as num FROM articulos WHERE prioridad=1 GROUP BY origen ORDER BY num DESC LIMIT {}".format(
                numero))
        result = curs.fetchall()
        html = f'<h1>IPs más problematicas</h1>'
        html += f'<ul>'
        for a in result:
            html += f'<ul><li>IP: {a[0]}</ul>'
        html += f'</ul>'
        con.close()
        return html

    @app.route('/DispositivosPeligrosos', methods=["POST"])
    def dispositivosPeligrosos():

        numero = int(request.form['numero3'])
        con = sqlite3.connect("bd1.db")
        curs = con.cursor()

        if request.form.get('menosPeligrosos'):
            curs.execute("SELECT dispositivos.id, dispositivos.ip, dispositivos.localizacion, dispositivos.responsable, analisis.vulnerabilidades_detectadas, ROUND(CAST(analisis.servicios_inseguros AS FLOAT)/ analisis.servicios * 100, 2) AS porcentaje FROM dispositivos INNER JOIN analisis ON analisis.id=dispositivos.analisis WHERE analisis.servicios>0 and porcentaje<33 ORDER BY porcentaje DESC LIMIT {}".format(numero))
            result = curs.fetchall()
            html = f'<h1>INFO MENOS PELIGROSOS</h1>'
            for a in result:
                html += f'<ul><li>ID: {a[0]} <li>IP:{a[1]} <li>LOCALIZACIÓN: {a[2]} <li>USUARIO:{a[3]} <li>VULNERABILIDADES DETECTADAS: {a[4]}</ul>'
        else:
            curs.execute("SELECT dispositivos.id, dispositivos.ip, dispositivos.localizacion, dispositivos.responsable,"
                         " analisis.vulnerabilidades_detectadas, "
                         "ROUND(CAST(analisis.servicios_inseguros AS FLOAT)/ analisis.servicios * 100, 2) AS porcentaje"
                         " FROM dispositivos INNER JOIN analisis ON analisis.id=dispositivos.analisis WHERE analisis.servicios>0"
                         " and porcentaje>33 ORDER BY porcentaje DESC LIMIT {}".format(numero))
            result = curs.fetchall()
            html = f'<h1>INFO MÁS PELIGROSOS</h1>'
            for a in result:
                html += f'<ul><li>ID: {a[0]} <li>IP:{a[1]} <li>LOCALIZACIÓN: {a[2]} <li>USUARIO:{a[3]} <li>VULNERABILIDADES DETECTADAS: {a[4]}</ul>'
        con.close()
        return html

    @app.route("/CVE")
    def CVEs():
        html = f'<h1>TOP 10 VULNERABILIDADES DEL CVE</h1>'
        respuesta = requests.get("https://cve.circl.lu/api/last")
        respuesta = respuesta.json()
        primeras = respuesta[:10]
        for row in primeras:
            html += f'<ul><li>ID: {row["id"]} <li>SUMMARY: {row["summary"]} <li>PUBLISHED: {row["Published"]}</ul>'

        return html

    @app.route("/login")
    def login():
        return render_template('login.html')

    @app.route("/urInfo", methods=["POST"])
    def getUrInfo():
        name = request.form['username']
        password = request.form['password']
        con = sqlite3.connect("bd1.db")
        curs = con.cursor()
        curs.execute("SELECT * from users_login WHERE name=?", (name,))
        row = curs.fetchone()
        if row:
            if row[2] == bcrypt.hashpw(password.encode('utf-8'), row[3]):
                html = f'<h1>BIENVENIDO {row[1]}</h1>'
                curs.execute(
                    "SELECT * FROM articulos INNER JOIN dispositivos ON dispositivos.ip=articulos.origen OR dispositivos.ip=articulos.destino WHERE dispositivos.responsable=? LIMIT 200",
                    (name,))
                result = curs.fetchall()
                for a in result:
                    html += f'<li>HORA:{a[0]} SID:{a[1]} CLASIFICACIÓN:{a[2]} PRIORIDAD:{a[3]} PROTOCOLO:{a[4]} ORIGEN:{a[5]} DESTINO:{a[6]} PUERTO:{a[7]}</li>'
                return html
            else:
                return "CONTRASEÑA O USUARIO INCORRECTO"
        else:
            return "CONTRASEÑA O USUARIO INCORRECTO"


    app.run(debug=True)

flask()
