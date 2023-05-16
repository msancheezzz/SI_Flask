import json
from sklearn import datasets, linear_model
import matplotlib.pyplot as pplot

# Prestamos atención a que en la pregunta 4 (ejercicio 2) se define un dipositivo peligroso
# como aquel que tiene más de un 33% de servicios inseguros

predict = json.load(open("IA\devices_IA_predecir_v2.json"))
train = json.load(open("IA\devices_IA_clases.json"))
linReg = linear_model.LinearRegression()
number = 0

# Incluiremos la información etiquetada en xtrain, y el resultado esperado en ytrain
xtrain = []
ytrain = []
for element in train:
    ytrain.append([element['peligroso']])
    if element['servicios'] == 0:
        xtrain.append([0])
    else:
        xtrain.append([element['servicios_inseguros']/element['servicios']])

xpredict = []
ypredict = []
for element in predict:
    if element['peligroso'] == 1:
        number += 1
    ypredict.append([element['peligroso']])
    if element['servicios'] == 0:
        xpredict.append([0])
    else:
        xpredict.append([element['servicios_inseguros']/element['servicios']])

linReg.fit(xtrain, ytrain)
prediction = linReg.predict(xpredict)

counter = 0
for result in prediction:
    if result >= 0.5:
        counter += 1
print("Expected result (number of positives): " + str(number))
print("Obtained result: " + str(counter))
print("Se aleja un " + str(abs(counter - number) * 100/len(ypredict)) + "% del resultado esperado")

# Nube de puntos de los valores reales del archivo que usaremos para hacer la predicción
pplot.scatter(xpredict, ypredict, color="black")
# Recta de regresión lineal de los datos predichos en base al mismo archivo
pplot.plot(xpredict, prediction, color="red", linewidth=1)
pplot.show()