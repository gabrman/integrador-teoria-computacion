import re

# --- Analizador Léxico ---
class Token:
    def __init__(self, tipo, valor):
        self.tipo = tipo
        self.valor = valor

    def __repr__(self):
        return f"Token({self.tipo}, '{self.valor}')"

class Lexer:
    def __init__(self, text):
        self.text = text
        self.pos = 0
        self.current_char = self.text[self.pos] if self.text else None
        # Definición de caracteres válidos para partes de dominio (letras, números, guiones)
        self.DOMAIN_CHARS = re.compile(r'[a-zA-Z0-9\-]')
        # Definición de caracteres válidos para ruta, consulta, fragmento
        # Ampliado para incluir más caracteres URL-seguros si no están cubiertos
        self.PATH_QUERY_FRAGMENT_CHARS = re.compile(r'[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]')


    def advance(self):
        self.pos += 1
        if self.pos < len(self.text):
            self.current_char = self.text[self.pos]
        else:
            self.current_char = None

    def peek(self, n=1):
        peek_pos = self.pos + n
        if peek_pos < len(self.text):
            return self.text[peek_pos]
        return None

    def skip_whitespace(self):
        while self.current_char is not None and self.current_char.isspace():
            self.advance()

    def get_next_token(self):
        self.skip_whitespace()

        if self.current_char is None:
            return Token('EOF', None)

        # Tokenización de protocolos (prioridad alta por ser prefijos fijos)
        if self.text[self.pos:].startswith('http://'):
            self.pos += 7
            self.current_char = self.text[self.pos] if self.pos < len(self.text) else None
            return Token('PROTOCOL', 'http')
        if self.text[self.pos:].startswith('https://'):
            self.pos += 8
            self.current_char = self.text[self.pos] if self.pos < len(self.text) else None
            return Token('PROTOCOL', 'https')

        # Tokenización de caracteres especiales individuales (ordenados por especificidad o frecuencia)
        if self.current_char == ':' and self.peek() == '/' and self.peek(2) == '/':
            self.advance(); self.advance(); self.advance()
            return Token('PROTOCOL_SEP', '://')

        if self.current_char == '.':
            self.advance()
            return Token('DOT', '.')

        if self.current_char == '/':
            self.advance()
            return Token('SLASH', '/')

        if self.current_char == '?':
            self.advance()
            return Token('QUESTION_MARK', '?')

        if self.current_char == '=':
            self.advance()
            return Token('EQUALS', '=')

        if self.current_char == '&':
            self.advance()
            return Token('AMPERSAND', '&')

        if self.current_char == '#':
            self.advance()
            return Token('HASH', '#')

        if self.current_char == ':': # Puerto
            self.advance()
            return Token('COLON', ':')

        if self.current_char == '@': # Userinfo
            self.advance()
            return Token('AT', '@')

        # FIX CRÍTICO: El token NUMBER DEBE ser reconocido antes que TEXT
        # Una secuencia de dígitos es un NUMBER, no un TEXT (que puede contener dígitos pero es más general).
        if self.current_char.isdigit():
            start = self.pos
            while self.current_char is not None and self.current_char.isdigit():
                self.advance()
            return Token('NUMBER', int(self.text[start:self.pos]))

        # TEXT (partes de dominio, segmentos de ruta que no son solo números, etc.)
        # Utiliza la regex DOMAIN_CHARS para identificar caracteres válidos en etiquetas de dominio.
        # Esto incluye letras, números y guiones, lo que cubre adecuadamente <Etiqueta> y <Palabra>.
        if self.DOMAIN_CHARS.match(self.current_char):
            start = self.pos
            while self.current_char is not None and self.DOMAIN_CHARS.match(self.current_char):
                self.advance()
            return Token('TEXT', self.text[start:self.pos])

        # Cualquier otro carácter que pueda ser parte de la URL pero no fue capturado
        # Esta es la "captura" de caracteres permitidos que no son parte de los tipos de tokens específicos.
        if self.PATH_QUERY_FRAGMENT_CHARS.match(self.current_char):
            char = self.current_char
            self.advance()
            return Token('SPECIAL_CHAR', char)

        raise Exception(f"Caracter no reconocido: '{self.current_char}' en posición {self.pos}")

# --- Analizador Sintáctico (Parser Recursivo Descendente) ---
class Parser:
    def __init__(self, lexer):
        self.lexer = lexer
        self.text = lexer.text
        self.current_token = self.lexer.get_next_token()

    def eat(self, token_type):
        if self.current_token.tipo == token_type:
            self.current_token = self.lexer.get_next_token()
        else:
            # Mensaje de error más detallado
            error_pos = self.lexer.pos - len(str(self.current_token.valor)) if self.current_token.valor is not None else self.lexer.pos
            raise Exception(f"Error de sintaxis: Se esperaba {token_type} pero se encontró {self.current_token.tipo} ('{self.current_token.valor}') en la URL en posición {error_pos}. Contexto: '{self.text[max(0, error_pos-10):error_pos+10]}'")

    # <URL> → <Protocolo> "://" [ <Usuario> "@" ] <Host> [ ":" <Puerto> ] [ "/" <Ruta> ] [ "?" <Parametros> ] [ "#" <Fragmento> ]
    def parse_url(self):
        protocol = self.protocol()
        # El lexer ya consume '://' si está junto al protocolo.
        # Si no, significa que se esperaba '://' después de 'http' o 'https'.
        if protocol not in ['http', 'https']:
             self.eat('PROTOCOL_SEP')

        userinfo = self.userinfo() # userinfo es opcional

        host = self.host()
        port = self.port() if self.current_token.tipo == 'COLON' else None
        path = self.path() if self.current_token.tipo == 'SLASH' else None
        query = self.query() if self.current_token.tipo == 'QUESTION_MARK' else None
        fragment = self.fragment() if self.current_token.tipo == 'HASH' else None

        # Después de parsear todo, solo debería quedar EOF
        if self.current_token.tipo != 'EOF':
            raise Exception(f"Error de sintaxis: Caracteres inesperados al final de la URL: '{self.current_token.valor}' en posición {self.lexer.pos}. Contexto: '{self.text[max(0, self.lexer.pos-10):self.lexer.pos+10]}'")

        url_ast = {
            'protocol': protocol,
            'userinfo': userinfo,
            'host': host,
            'port': port,
            'path': path,
            'query': query,
            'fragment': fragment
        }
        return url_ast

    # <Protocolo> → "http" | "https"
    def protocol(self):
        token = self.current_token
        self.eat('PROTOCOL')
        return token.valor

    # <Usuario> "@" [ ":" <Contraseña> ]
    # Retorna un diccionario con 'user' y 'password' o None
    def userinfo(self):
        # Guardar estado para retroceder si no es userinfo
        lexer_original_pos = self.lexer.pos
        lexer_original_current_char = self.lexer.current_char
        parser_original_token = self.current_token

        user = None
        password = None

        try:
            if self.current_token.tipo == 'TEXT': # Potencial nombre de usuario
                user = self.current_token.valor
                self.eat('TEXT')

                # Chequea si hay contraseña (opcional)
                if self.current_token.tipo == 'COLON':
                    self.eat('COLON')
                    if self.current_token.tipo == 'TEXT' or self.current_token.tipo == 'NUMBER': # Contraseña puede ser texto o número
                        password = str(self.current_token.valor)
                        self.eat(self.current_token.tipo)
                    else:
                        raise Exception("Se esperaba texto/número de contraseña después de ':' en userinfo.")

                if self.current_token.tipo == 'AT': # Obligatorio @ para considerar userinfo
                    self.eat('AT')
                    return {'user': user, 'password': password}
                else:
                    raise Exception("Se esperaba '@' después de userinfo.") # No hay '@', no es userinfo
            else:
                raise Exception("No se encontró texto de userinfo.") # No hay texto, no es userinfo

        except Exception:
            # Si no se encontró el patrón de userinfo o hubo un error, revertir el estado
            self.lexer.pos = lexer_original_pos
            self.lexer.current_char = self.lexer.text[self.lexer.pos] if self.lexer.pos < len(self.lexer.text) else None
            self.current_token = parser_original_token
            return None # No se parseó userinfo


    # <Host> → <Dominio> | <DireccionIP>
    # (La gramática del usuario también incluye <Usuario> "@" <DominioSospechoso> aquí,
    # pero eso se maneja como una rama separada en parse_url con userinfo opcional
    # para mantener el host genérico y la "sospecha" en el detector)
    def host(self):
        lexer_original_pos = self.lexer.pos
        lexer_original_current_char = self.lexer.current_char
        parser_original_token = self.current_token

        # Intentar parsear como IP (solo IPv4 por simplicidad)
        try:
            ip_octets = []

            for i in range(4):
                if self.current_token.tipo == 'NUMBER':
                    if not (0 <= self.current_token.valor <= 255):
                         raise Exception(f"Octeto IP '{self.current_token.valor}' fuera de rango (0-255).")
                    ip_octets.append(str(self.current_token.valor))

                    self.eat('NUMBER')

                    if i < 3: # Si no es el último octeto, esperamos un punto
                        if self.current_token.tipo == 'DOT':
                            self.eat('DOT')
                        else:
                            raise Exception(f"Se esperaba '.' después del octeto {i} de la IP, se encontró {self.current_token.tipo}.")
                else:
                    raise Exception(f"Se esperaba NÚMERO para el octeto {i} de la IP, se encontró {self.current_token.tipo}.")

            # Si se parsearon 4 octetos y 3 puntos, verificamos el siguiente token para confirmar que es una IP limpia.
            # Los tokens 'SPECIAL_CHAR' pueden ser parte de un path si la IP es parte de un subdominio/usuario (e.g. 1.2.3.4.google.com)
            # Por eso, solo se considera IP si los siguientes tokens son claramente delimitadores de URL.
            if self.current_token.tipo in ['SLASH', 'COLON', 'QUESTION_MARK', 'HASH', 'EOF']:
                return {'type': 'IP', 'value': '.'.join(ip_octets)}
            else:
                # Si el siguiente token es parte de un dominio (ej. 1.2.3.4.google.com), no es una IP pura.
                raise Exception("Cadena similar a IP seguida de caracteres de dominio, se trata como dominio.")

        except Exception:
            # Si el parseo IP falla, restaurar el estado original del lexer y parser para intentar como dominio
            self.lexer.pos = lexer_original_pos
            self.lexer.current_char = self.lexer.text[self.lexer.pos] if self.lexer.pos < len(self.lexer.text) else None
            self.current_token = parser_original_token

            # --- Lógica para Dominio ---
            # <Dominio> → <Subdominios>? <NombreDominio> "." <TLD>
            # <Subdominios> → <Etiqueta> "." <Subdominios> | <Etiqueta> "."
            # <NombreDominio> → <Etiqueta>
            # <Etiqueta> → <Letra> <EtiquetaResto> (implementado por Lexer como TEXT/NUMBER)

            parts = [] # Almacenará subdominios, nombre de dominio y TLD
            while self.current_token.tipo in ['TEXT', 'NUMBER']: # Las etiquetas de dominio pueden ser texto o números
                part_value = str(self.current_token.valor)
                parts.append(part_value)

                self.eat(self.current_token.tipo)

                if self.current_token.tipo == 'DOT':
                    self.eat('DOT')
                else:
                    break # No más puntos, la parte de dominio termina

            if not parts:
                raise Exception("Error: Host (dominio o IP) esperado o mal formado.")

            # El último elemento es el TLD
            tld = parts.pop()
            if not tld.isalpha(): # Los TLDs comunes son solo letras.
                raise Exception(f"Error: '{tld}' no es un TLD válido (solo letras).")

            # El penúltimo elemento es el NombreDominio
            domain_name = parts.pop() if parts else ""

            # Los elementos restantes son los subdominios
            subdomains = parts

            return {
                'type': 'DOMAIN',
                'subdomains': subdomains,
                'domain_name': domain_name,
                'tld': tld
            }

    # [ ":" <Puerto> ]
    def port(self):
        self.eat('COLON')
        token = self.current_token
        self.eat('NUMBER')
        if not (0 <= token.valor <= 65535):
            raise Exception(f"Puerto fuera de rango (0-65535): {token.valor}")
        return token.valor

    # <Ruta> → <Segmento> "/" <Ruta> | <Segmento> (Implementación iterativa de segmentos)
    def path(self):
        path_str = ""
        while self.current_token.tipo == 'SLASH':
            path_str += self.current_token.valor # Añade el slash
            self.eat('SLASH')
            # Captura el segmento hasta el siguiente slash, ?, # o EOF
            # Se asegura de consumir todos los caracteres válidos para un segmento
            segment = self._get_chars_until(['SLASH', 'QUESTION_MARK', 'HASH', 'EOF'])
            path_str += segment
            if self.current_token.tipo != 'SLASH': # Si no es un slash, el path termina o continúa con query/fragment
                break
        return path_str if path_str else None

    # <Parametros> → <Parametro> "&" <Parametros> | <Parametro>
    def query(self):
        self.eat('QUESTION_MARK')
        params = []
        params.append(self.query_parameter())
        while self.current_token.tipo == 'AMPERSAND':
            self.eat('AMPERSAND')
            params.append(self.query_parameter())
        return params

    # <Parametro> → <Clave> "=" <Valor>
    def query_parameter(self):
        name = self._get_chars_until(['EQUALS', 'AMPERSAND', 'HASH', 'EOF'])
        if self.current_token.tipo == 'EQUALS':
            self.eat('EQUALS')
            value = self._get_chars_until(['AMPERSAND', 'HASH', 'EOF'])
        else:
            value = "" # Parámetro sin valor (ej. ?param)
        return {'name': name, 'value': value}

    # Helper para consumir caracteres hasta encontrar un tipo de token de parada
    def _get_chars_until(self, stop_token_types):
        chars = []
        # Consume tokens que son TEXT, NUMBER o SPECIAL_CHAR, ya que pueden formar parte de un segmento.
        while self.current_token.tipo not in stop_token_types and self.current_token.tipo != 'EOF':
            if self.current_token.tipo in ['TEXT', 'NUMBER', 'SPECIAL_CHAR']:
                chars.append(str(self.current_token.valor))
                self.current_token = self.lexer.get_next_token()
            else:
                # Si encontramos un token inesperado, detenemos la captura del segmento
                break
        return ''.join(chars)

    # [ "#" <Fragmento> ]
    def fragment(self):
        self.eat('HASH')
        return self._get_chars_until(['EOF'])

# --- Lógica de Detección de Sospecha ---
class PhishingDetector:
    def __init__(self):
        self.legitimate_domains = {
            'google.com', 'microsoft.com', 'paypal.com', 'amazon.com', 'facebook.com',
            'apple.com', 'unne.edu.ar', 'github.com', 'developer.mozilla.org',
            'login.microsoftonline.com', 'outlook.com', 'onedrive.live.com',
            'drive.google.com', 'mail.google.com', 'docs.google.com'
        }
        self.suspicious_tlds = {
            'xyz', 'top', 'bid', 'club', 'online', 'loan', 'click', 'icu', 'gq', 'ml', 'cf', 'tk',
            'buzz', 'site', 'pw', 'press', 'stream', 'party', 'pro'
        }

        # Palabras clave sospechosas en el dominio (ej. login.paypal.com -> paypal podría ser palabra clave)
        # Basado en <PalabraSospechosaDominio> y otras que son útiles para el dominio
        self.suspicious_domain_keywords = {
            'login', 'secure', 'verify', 'paypal', 'banco', 'update', 'confirm', 'reset', 'account', 'security', 'signin'
        }

        # Palabras clave sospechosas en la ruta o parámetros de consulta
        # Basado en <PalabraSospechosaRuta> y otras generales
        self.suspicious_path_query_keywords = {
            'login', 'signin', 'verify', 'account', 'update', 'security', 'secure',
            'webmail', 'bank', 'confirm', 'password', 'alert', 'support', 'billing',
            'free', 'prize', 'winner', 'clickhere', 'urgent', 'payment', 'token', 'reset'
        }

    def is_suspicious(self, parsed_url_ast):
        # 1. Chequeo de Host basado en IP
        if parsed_url_ast['host'] and parsed_url_ast['host']['type'] == 'IP':
            return "Sospechosa: El host es una dirección IP, común en sitios no legítimos."

        # Chequeos basados en el dominio
        if parsed_url_ast['host'] and parsed_url_ast['host']['type'] == 'DOMAIN':
            domain_name = parsed_url_ast['host']['domain_name']
            tld = parsed_url_ast['host']['tld']
            subdomains = parsed_url_ast['host']['subdomains']

            full_domain_str = f"{domain_name}.{tld}"
            full_host_str = ".".join(subdomains + [domain_name, tld])

            # 2. Chequeo de TLD Sospechoso
            if tld in self.suspicious_tlds:
                return f"Sospechosa: El TLD '{tld}' es comúnmente asociado con dominios de phishing."

            # 3. Chequeo de Dominio Engañoso y Typosquatting
            # Verificar si el nombre de dominio principal es una palabra clave de phishing
            if domain_name.lower() in self.suspicious_domain_keywords:
                 return f"Sospechosa: El nombre de dominio '{domain_name}' es una palabra clave de phishing."

            # Verificar si CUALQUIER subdominio es una palabra clave de phishing
            for sub in subdomains:
                if sub.lower() in self.suspicious_domain_keywords:
                    return f"Sospechosa: El subdominio '{sub}' es una palabra clave de phishing."

            # Si el dominio principal + TLD no es legítimo, pero un subdominio es un dominio legítimo conocido
            if full_domain_str not in self.legitimate_domains:
                for legit_base in self.legitimate_domains:
                    legit_parts = legit_base.split('.')
                    # Chequear si un dominio legítimo completo aparece como subdominio
                    # Esto detectaría algo como https://google.com.malicious.xyz
                    if legit_base in subdomains: # Direct match of known legitimate domain as a subdomain
                        return f"Sospechosa: El dominio legítimo '{legit_base}' aparece como subdominio de un host desconocido: '{full_host_str}'."

                    # Chequear si el dominio principal del phishing es un typo de un dominio legítimo
                    # Asegurarse de que el TLD también coincida para reducir falsos positivos
                    if (len(legit_parts) > 1 and
                          self._levenshtein_distance(domain_name, legit_parts[0]) <= 2 and # Levenshtein distance for typos
                          tld == legit_parts[1] and # TLD must match
                          full_domain_str not in self.legitimate_domains): # And it's not in our list of legitimate domains
                            return f"Sospechosa: Posible typosquatting (similar a '{legit_base}')."

            # 4. Chequeo de Subdominios Excesivos (Heurística)
            if len(subdomains) > 3:
                return "Sospechosa: Demasiados subdominios, lo que puede ser una señal de ofuscación."

        # 5. Chequeo de Palabras Clave Sospechosas en Ruta o Parámetros
        path = parsed_url_ast['path']
        query = parsed_url_ast['query']

        if path:
            path_segments = [s for s in path.split('/') if s] # Split and remove empty strings
            for segment in path_segments:
                for keyword in self.suspicious_path_query_keywords:
                    # Usar 'in' para que coincida si el keyword es una subcadena del segmento
                    if keyword in segment.lower():
                        return f"Sospechosa: Palabra clave '{keyword}' encontrada en el segmento de ruta '{segment}'."

        if query:
            for param in query:
                for keyword in self.suspicious_path_query_keywords:
                    if keyword in param['name'].lower() or keyword in param['value'].lower():
                        return f"Sospechosa: Palabra clave '{keyword}' encontrada en los parámetros de consulta."
                # Detección de redirecciones a dominios externos en query params
                if param['name'].lower() in ['redirect', 'url', 'next', 'returnurl'] and '://' in str(param['value']):
                    # Intenta parsear la URL de redirección para un chequeo más profundo (opcional, puede ser complejo)
                    # Por simplicidad, un chequeo básico si el host original no está en el valor de redirección
                    if parsed_url_ast['host'] and parsed_url_ast['host']['type'] == 'DOMAIN':
                        original_host_full = parsed_url_ast['host']['domain_name'] + '.' + parsed_url_ast['host']['tld']
                        if original_host_full not in str(param['value']):
                            return f"Sospechosa: Parámetro de redirección apuntando a un dominio externo."

        # 6. Chequeo de Protocolo HTTP para sitios que deberían ser HTTPS (heurística)
        if parsed_url_ast['protocol'] == 'http' and parsed_url_ast['host'] and parsed_url_ast['host']['type'] == 'DOMAIN':
            domain_name = parsed_url_ast['host']['domain_name']
            tld = parsed_url_ast['host']['tld']
            full_domain_check = f"{domain_name}.{tld}"

            if full_domain_check in self.legitimate_domains:
                return "Sospechosa: Uso de HTTP para un dominio conocido que debería usar HTTPS (posible degradación)."

        # 7. Chequeo de Userinfo (Usuario@Dominio)
        if parsed_url_ast['userinfo']:
            user = parsed_url_ast['userinfo']['user']
            # Puedes añadir heurísticas específicas para user/password aquí, ej:
            # if user.lower() in ['admin', 'root', 'test'] or parsed_url_ast['userinfo']['password'] == 'password':
            #    return "Sospechosa: Userinfo con credenciales débiles/comunes."

            return "Sospechosa: La URL contiene información de usuario (userinfo) antes del host, lo cual es poco común en sitios legítimos y a menudo usado en phishing."


        return "Fiable: La URL parece estructuralmente correcta y no presenta patrones comunes de phishing."

    def _levenshtein_distance(self, s1, s2):
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]


# --- Función principal para analizar una URL ---
def analyze_url(url_string):
    try:
        lexer = Lexer(url_string)
        parser = Parser(lexer)
        parsed_ast = parser.parse_url()

        detector = PhishingDetector()
        verdict = detector.is_suspicious(parsed_ast)

        return {
            'status': 'success',
            'url': url_string,
            'parsed_data': parsed_ast,
            'verdict': verdict
        }
    except Exception as e:
        return {
            'status': 'error',
            'url': url_string,
            'message': f"Error al analizar la URL: {str(e)}"
        }