from parser_url import analyze_url  # Asegurate de que tu archivo se llame analizador.py

# Lista de URLs ficticias para probar
urls = [
    "http://secure-login.paypa1.com/verify",
    "http://microsoft-support-reset-password.tk",
    "https://accounts.google.com/signin",
    "https://virtual-moodle.unne.edu.ar",
    "https://www.google.com/?hl=es",
    "https://docs.google.com/",
    "https://www.eset.com/ar/",
    "https://github.com/gabrman/integrador-teoria-computacion"
]

# Ejecutar el análisis para cada URL
for url in urls:
    resultado = analyze_url(url)
    print(f"URL: {url}")
    if resultado['status'] == 'success':
        print(f"Veredicto: {resultado['verdict']}")
        print("Datos parseados:")
        for clave, valor in resultado['parsed_data'].items():
            print(f"  {clave}: {valor}")
    else:
        print(f"Error: {resultado['message']}")
