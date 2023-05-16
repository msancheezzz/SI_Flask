from sklearn.ensemble import RandomForestClassifier
import json
from sklearn import datasets, linear_model
import matplotlib.pyplot as pplot
import graphviz
from sklearn.tree import export_graphviz

# Prestamos atención a que en la pregunta 4 (ejercicio 2) se define un dipositivo peligroso
# como aquel que tiene más de un 33% de servicios inseguros

predict = json.load(open("IA\devices_IA_predecir_v2.json"))
train = json.load(open("IA\devices_IA_clases.json"))
randForest = RandomForestClassifier()
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
expectedresults = []
for element in predict:
    if element['peligroso'] == 0:
        number += 1
    expectedresults.append([element['peligroso']])
    if element['servicios'] == 0:
        xpredict.append([0])
    else:
        xpredict.append([element['servicios_inseguros']/element['servicios']])

randForest.fit(xtrain, ytrain)
prediction = randForest.predict(xpredict)

counter = 0
for result in prediction:
    if result >= 0.5:
        counter += 1

print(prediction)
print("Expected result (number of positives): " + str(number))
print("Obtained result: " + str(counter))
print("Se aleja un " + str(abs(counter - number) * 100/len(expectedresults)) + "% del resultado esperado")
print(len(randForest.estimators_))

# Hacemos lo mismo que con DecisionTree pero para diferentes estimadores (los arboles que componen el "forest")
plot = export_graphviz(randForest.estimators_[2], out_file=None, feature_names=["danger_percentage"], class_names=["no_peligroso","peligroso"])
grafico = graphviz.Source(plot)
grafico.view()
