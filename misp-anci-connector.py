import requests
import sys
import datetime
import smtplib
from email.message import EmailMessage
from requests.auth import HTTPBasicAuth
from pymisp import PyMISP, MISPEvent, MISPAttribute
# Nota: La importacion de urllib3 para deshabilitar warnings fue eliminada
# ya que no es necesaria para la logica principal y se recomienda no usar.

# --- 1. CONFIGURACION DE ACCESO (¡REEMPLAZAR CON VALORES REALES!) ---

# 1a. API Externa (ANCI / CSIRT Nacional)
# La URL base de la API
ANCI_API_URL = "https://apimisp.csirt.gob.cl"
# Credenciales de usuario para la API de ANCI/CSIRT
ANCI_USER = "TU_USUARIO_ANCI"
ANCI_PASS = "TU_PASSWORD_ANCI"

# 1b. Tu MISP Local (Siptel o similar)
# URL de tu instancia MISP
MISP_LOCAL_URL = "https://TU_IP_O_DOMINIO_MISP"
# Clave API de tu MISP
MISP_LOCAL_KEY = "TU_MISP_API_KEY"
# Si tu MISP usa un certificado autofirmado (se mantiene en False por defecto para entornos internos)
MISP_VERIFY_CERT = False

# --- 1c. CONFIGURACION DE EMAIL (¡REEMPLAZAR CON VALORES REALES!) ---
# Poner en False para desactivar el envio de correos
EMAIL_ENABLED = True
EMAIL_HOST = "mail.TU_DOMINIO.cl"
EMAIL_PORT = 465
EMAIL_USER = "tu_usuario_correo"
# Se usa r"..." (raw string) por si la contrasena contiene backslash
EMAIL_PASSWORD = "TU_PASSWORD_CORREO"
EMAIL_SENDER = "remitente@tu_dominio.cl"
EMAIL_RECIPIENTS = ["soc@tu_dominio.cl", "otro_contacto@tu_dominio.cl"]


def get_anci_token():
    """
    Se autentica contra el endpoint /token para obtener un Bearer Token JWT.
    """
    print("Obteniendo token de autenticacion desde ANCI...")
    token_url = f"{ANCI_API_URL}/token"
    auth_payload = {
        "username": ANCI_USER,
        "password": ANCI_PASS
    }
    try:
        response = requests.post(token_url, json=auth_payload, timeout=10)

        if response.status_code == 200:
            token = response.json().get('access_token')
            print("Token Bearer obtenido exitosamente!")
            return token
        else:
            print(f"[ERROR] Fallo al obtener token: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        print(f"[ERROR] No se pudo conectar a {token_url}: {e}")
        return None

def process_iocs(misp_event, headers, payload, endpoint, response_key, tipo_mapeo):
    """
    Funcion generica para procesar endpoints de IoC simples (dominios, urls).
    """
    ioc_count = 0
    url = f"{ANCI_API_URL}{endpoint}"
    print(f"\nObteniendo indicadores de: {endpoint}...")

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=120)

        if response.status_code == 200:
            data = response.json().get('response', {})
            iocs = data.get(response_key, [])

            if not iocs:
                print(f"No se encontraron nuevos indicadores en '{endpoint}'.")
                return 0

            print(f"Exito! Se obtuvieron {len(iocs)} indicadores de '{response_key}'.")
            for item in iocs:
                valor = item.get('valor')
                tipo_misp = tipo_mapeo.get(item.get('tipo'), item.get('tipo'))
                if valor and tipo_misp:
                    attr = MISPAttribute()
                    attr.type = tipo_misp
                    attr.value = valor
                    attr.comment = "Importado desde ANCI API"
                    attr.to_ids = True
                    misp_event.add_attribute(**attr)
                    ioc_count += 1
        elif response.status_code == 404:
            print(f"No se encontraron resultados para el rango de fechas en '{endpoint}'.")
        else:
            print(f"[ADVERTENCIA] API devolvio error para '{endpoint}': {response.status_code} - {response.text}")

    except Exception as e:
        print(f"[ADVERTENCIA] No se pudo conectar a '{endpoint}': {e}")

    return ioc_count

def process_nested_iocs(misp_event, headers, payload, endpoint, response_key):
    """
    Funcion para procesar endpoints anidados (ip_amenazas, hashes).
    """
    ioc_count = 0
    url = f"{ANCI_API_URL}{endpoint}"
    print(f"\nObteniendo indicadores de: {endpoint}...")

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=120)

        if response.status_code == 200:
            data = response.json().get('response', {})
            amenazas_dict = data.get(response_key, {})
            if not amenazas_dict:
                print(f"No se encontraron nuevos indicadores en '{endpoint}'.")
                return 0

            print(f"Exito! Procesando {len(amenazas_dict)} grupos de amenazas...")
            for malware_name, ioc_list in amenazas_dict.items():
                for item in ioc_list:
                    valor = item.get('valor')
                    tipo_misp = item.get('tipo')

                    if valor and tipo_misp:
                        attr = MISPAttribute()
                        attr.type = tipo_misp
                        attr.value = valor
                        attr.comment = f"Amenaza: {malware_name} (Importado desde ANCI API)"
                        attr.to_ids = True
                        misp_event.add_attribute(**attr)
                        ioc_count += 1

        elif response.status_code == 404:
            print(f"No se encontraron resultados para el rango de fechas en '{endpoint}'.")
        else:
            print(f"[ADVERTENCIA] API devolvio error para '{endpoint}': {response.status_code} - {response.text}")

    except Exception as e:
        print(f"[ADVERTENCIA] No se pudo conectar a '{endpoint}': {e}")

    return ioc_count

# --- FUNCION DE EMAIL ---
def send_notification_email(event_url, event_id, ioc_count):
    """
    Envia un correo electronico de notificacion.
    """
    if not EMAIL_ENABLED:
        print("El envio de correo esta desactivado. Omitiendo.")
        return

    print("Enviando correo de notificacion...")

    # 1. Crear el mensaje
    msg = EmailMessage()
    msg['Subject'] = f"MISP: Nuevo Evento Creado (ID: {event_id}) - {ioc_count} IoCs de ANCI"
    msg['From'] = EMAIL_SENDER
    msg['To'] = ", ".join(EMAIL_RECIPIENTS)

    body = f"""
    Hola equipo SOC,

    El conector de ANCI se ha ejecutado exitosamente.

    Se creo un nuevo evento en MISP con los ultimos indicadores de compromiso.

    - Evento: {event_url}
    - Indicadores anadidos: {ioc_count}

    Saludos,
    Conector (synsoc)
    SIPTEL (o nombre de tu organizacion)

    """
    msg.set_content(body)

    # 2. Enviar el mensaje
    try:
        if EMAIL_PORT == 465:
            # Usar si el puerto es 465 (SSL)
            print(f"Conectando a {EMAIL_HOST}:{EMAIL_PORT} via SSL...")
            server = smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT)
        else:
            # Usar si el puerto es 587 (STARTTLS) o 25 (sin cifrado)
            print(f"Conectando a {EMAIL_HOST}:{EMAIL_PORT}...")
            server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
            if EMAIL_PORT == 587:
                server.starttls()

        print("Iniciando sesion SMTP...")
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        print("Sesion SMTP exitosa. Enviando mensaje...")
        server.send_message(msg)
        server.quit()
        print("¡Correo de notificacion enviado!")

    except Exception as e:
        print(f"[ADVERTENCIA] No se pudo enviar el correo de notificacion: {e}")
# --- FIN DE LA FUNCION DE EMAIL ---


def main():
    print(f"--- [v3.4 - Con Email] Iniciando conector ANCI-MISP ---")

    # 1. Obtener Token Bearer
    token = get_anci_token()
    if not token:
        sys.exit(1)

    headers = {"Authorization": f"Bearer {token}"}

    # 2. Definir Payload de Fechas (Ultimos 30 dias)
    now = datetime.datetime.now()
    past = now - datetime.timedelta(days=30)
    date_payload = {
        "fecha_desde": past.strftime('%Y-%m-%d %H:%M:%S'),
        "fecha_hasta": now.strftime('%Y-%m-%d %H:%M:%S')
    }
    print(f"Buscando indicadores desde {date_payload['fecha_desde']} hasta {date_payload['fecha_hasta']}")

    # 3. Conectar a MISP Local
    print(f"Conectando a MISP local en {MISP_LOCAL_URL}...")
    try:
        misp = PyMISP(MISP_LOCAL_URL, MISP_LOCAL_KEY, MISP_VERIFY_CERT)
        print("Conexion exitosa a MISP local!")
    except Exception as e:
        print(f"[ERROR] No se pudo conectar a MISP local: {e}")
        sys.exit(1)

    # 4. Preparar Evento en MISP
    fecha_hoy = now.strftime('%Y-%m-%d')
    event = MISPEvent()
    event.info = f"Indicadores Agregados - CSIRT Nacional (ANCI) - {fecha_hoy}"
    event.add_tag("CSIRT-Nacional-Chile")
    event.add_tag("Fuente:API-ANCI")

    total_added_iocs = 0
    print(f"Preparando evento: '{event.info}'")

    # 5. Procesar cada endpoint y anadir tags especificos
    print("Procesando indicadores por tipo...")

    # IPs (Anidado)
    ip_count = process_nested_iocs(event, headers, date_payload,
                                   endpoint="/ioc/ip_amenazas",
                                   response_key="amenazas")
    if ip_count > 0:
        event.add_tag("IOC-IPV4")
    total_added_iocs += ip_count

    # Hashes (Anidado)
    hash_count = process_nested_iocs(event, headers, date_payload,
                                     endpoint="/ioc/hashes",
                                     response_key="amenazas")
    if hash_count > 0:
        event.add_tag("IOC-HASH")
    total_added_iocs += hash_count

    # Dominios (Simple)
    domain_count = process_iocs(event, headers, date_payload,
                                 endpoint="/ioc/dominios",
                                 response_key="dominios",
                                 tipo_mapeo={'hostname': 'hostname'})
    if domain_count > 0:
        event.add_tag("IOC-DOMINIOS")
    total_added_iocs += domain_count

    # URLs (Simple)
    url_count = process_iocs(event, headers, date_payload,
                             endpoint="/ioc/urls",
                             response_key="urls",
                             tipo_mapeo={'link': 'url'})
    if url_count > 0:
        event.add_tag("IOC-URL")
    total_added_iocs += url_count

    print("Procesamiento de indicadores completado.")


    # 6. Guardar el Evento en MISP
    if total_added_iocs > 0:
        print("\n-------------------------------------------------")
        print(f"Anadiendo {total_added_iocs} indicadores totales al evento...")
        try:
            # Se elimina 'requests.packages.urllib3.disable_warnings()'

            evento_creado = misp.add_event(event)

            if isinstance(evento_creado, dict) and 'Event' in evento_creado and 'id' in evento_creado['Event']:
                event_id = evento_creado['Event']['id']
                event_url = f"{MISP_LOCAL_URL}/events/view/{event_id}"

                print("EXITO!!")
                print(f"Evento creado/actualizado en tu MISP: {event_url}")
                print("-------------------------------------------------")

                # Llamar a la funcion de email!
                send_notification_email(event_url, event_id, total_added_iocs)
            else:
                print("[ERROR] El evento se envio, pero MISP devolvio una respuesta inesperada.")
                print(f"Respuesta recibida: {evento_creado}")

        except Exception as e:
            print(f"[ERROR] No se pudo crear el evento en MISP: {e}")
    else:
        print("\n-------------------------------------------------")
        print("No se obtuvieron nuevos indicadores. No se creara ningun evento.")
        print("-------------------------------------------------")

# --- EJECUTAR SCRIPT ---
if __name__ == "__main__":
    main()
