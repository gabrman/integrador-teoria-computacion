# app.py
from flask import Flask, render_template, request, jsonify
from parser_url import analyze_url # Importa tu función de análisis desde parser_url.py

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url_input']
        result = analyze_url(url)
        return render_template('index.html', url_input=url, result=result)
    return render_template('index.html', url_input='', result=None)

# Opcional: una API para que JavaScript la llame directamente si quieres una interfaz más dinámica
@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'status': 'error', 'message': 'URL no proporcionada'}), 400
    
    result = analyze_url(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True) # debug=True recarga el servidor automáticamente al hacer cambios