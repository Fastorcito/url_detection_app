from flask import Blueprint, render_template, request
import pickle
from preprocessing import preprocess_url

main = Blueprint('main', __name__)


with open('ia_models/model_knn.pkl', 'rb') as f:
    model_knn = pickle.load(f)


with open('ia_models/model_svm.pkl', 'rb') as f:
    model_svm = pickle.load(f)

with open('ia_models/model_rnn.pkl', 'rb') as f:
    model_rnn = pickle.load(f)





models = {
    'model_1': model_knn,
    'model_2': model_svm,
    'model_3': model_rnn
}

def hacer_prediccion(url, modelo):
    features_df = preprocess_url(url)
    model = models.get(modelo)
    if model is not None:
        prediction = model.predict(features_df)
        return prediction[0]
    else:
        return None

@main.route('/', methods=['GET', 'POST'])
def index():
    porcentaje_posibilidad = None
    
    if request.method == 'POST':
        url = request.form['url']
        modelo = request.form['model']
        porcentaje_posibilidad = hacer_prediccion(url, modelo)
    
    return render_template('index.html', porcentaje_posibilidad=porcentaje_posibilidad)
