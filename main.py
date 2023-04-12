import json
import sqlite3
import pandas as pd
import matplotlib as mp
from flask import Flask, jsonify
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

############## RELLENAR TABLAS #############################3

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
            <h1>FUFA</h1>
            <form action="/DispositivosProblematicos" method="POST">
                <input type="number" id="numero" name="numero">
                <button type="submit">ENVIAR</button>
            </form>
            <ul></ul>
            <form action="/IPProblematicas" method="POST">
                <input type="number" id="numero2" name="numero2">
                
                <button type="submit">ENVIAR</button>
            </form>
            <ul></ul>
            <form action="/DispositivosPeligrosos" method="POST">
                <input type="number" id="numero3" name="numero3">
                <input type="checkbox" name="masPeligrosos">
                <input type="checkbox" name="menosPeligrosos">
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
            html += f'<li>{a[0]} {a[1]}</li>'
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
            html += f'<li>{a[0]} {a[1]}</li>'
        html += f'</ul>'
        con.close()
        return html

    @app.route('/DispositivosPeligrosos', methods=["POST"])
    def dispositivosPeligrosos():

        numero = int(request.form['numero3'])
        con = sqlite3.connect("bd1.db")
        curs = con.cursor()
        curs.execute(
            "SELECT dispositivos.id, ROUND(CAST(analisis.servicios_inseguros AS FLOAT)/ analisis.servicios * 100, 2) AS porcentaje FROM dispositivos INNER JOIN analisis ON analisis.id=dispositivos.analisis WHERE analisis.servicios>0 and porcentaje>33 ORDER BY porcentaje DESC LIMIT {}".format(
                numero))
        result = curs.fetchall()
        html = f'<h1>Dispositivos más peligrosos</h1>'
        html += f'<ul>'
        for a in result:
            html += f'<li>{a[0]} {a[1]}</li>'
        html += f'</ul>'
        if request.form.get('masPeligrosos'):
            curs.execute("SELECT dispositivos.id, dispositivos.ip, dispositivos.localizacion, dispositivos.responsable, analisis.vulnerabilidades_detectadas, ROUND(CAST(analisis.servicios_inseguros AS FLOAT)/ analisis.servicios * 100, 2) AS porcentaje FROM dispositivos INNER JOIN analisis ON analisis.id=dispositivos.analisis WHERE analisis.servicios>0 and porcentaje>33 ORDER BY porcentaje DESC LIMIT {}".format(numero))
            result = curs.fetchall()
            html += f'<h1>INFO MÁS PELIGROSOS</h1>'
            for a in result:
                html += f'<li>{a[0]} {a[1]} {a[2]} {a[3]} {a[4]}'
        if request.form.get('menosPeligrosos'):
            curs.execute("SELECT dispositivos.id, dispositivos.ip, dispositivos.localizacion, dispositivos.responsable, analisis.vulnerabilidades_detectadas, ROUND(CAST(analisis.servicios_inseguros AS FLOAT)/ analisis.servicios * 100, 2) AS porcentaje FROM dispositivos INNER JOIN analisis ON analisis.id=dispositivos.analisis WHERE analisis.servicios>0 and porcentaje<33 ORDER BY porcentaje DESC LIMIT {}".format(numero))
            result = curs.fetchall()
            html += f'<h1>INFO MENOS PELIGROSOS</h1>'
            for a in result:
                html += f'<li>{a[0]} {a[1]} {a[2]} {a[3]} {a[4]}'
        con.close()
        return html

    @app.route("/CVE")
    def CVEs():
        respuesta = requests.get("https://cve.circl.lu/api/last")
        respuesta = respuesta.json()
        primeras = respuesta[:10]
        return primeras


    app.run(debug=True)

flask()