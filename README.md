## 🛡️ Conector MISP | CSIRT Nacional (ANCI)

[](https://www.google.com/search?q=LICENSE)
[](https://www.google.com/search?q=https://www.csirt.gob.cl/)
[](https://www.google.com/search?q=https://github.com/tu-usuario/tu-repositorio)

Script de Python para importar automáticamente Indicadores de Compromiso (IoCs) del CSIRT Nacional de Chile (ANCI) a una instancia local de MISP.

### 📋 Tabla de Contenidos

1.  [Descripción](https://www.google.com/search?q=%23-descripci%C3%B3n)
2.  [Requisitos](https://www.google.com/search?q=%23-requisitos)
3.  [Instalación](https://www.google.com/search?q=%23-instalaci%C3%B3n)
4.  [Configuración de Credenciales](https://www.google.com/search?q=%23-configuraci%C3%B3n-de-credenciales)
      * [Variables de Entorno (Recomendado)](https://www.google.com/search?q=%23variables-de-entorno-recomendado)
      * [Configuración de Email](https://www.google.com/search?q=%23configuraci%C3%B3n-de-email)
5.  [Ejecución](https://www.google.com/search?q=%23-ejecuci%C3%B3n)
6.  [Estructura y Mapeo](https://www.google.com/search?q=%23-estructura-y-mapeo)
7.  [Contribuciones y Licencia](https://www.google.com/search?q=%23-contribuciones-y-licencia)

-----

## 📌 Descripción

Este conector es una herramienta esencial para equipos de Ciberseguridad que operan MISP y desean enriquecer sus plataformas con inteligencia de amenazas específica de la región. El script realiza los siguientes pasos:

1.  **Autenticación**: Obtiene un *Bearer Token* JWT de la API de ANCI.
2.  **Recuperación de IoCs**: Consulta los endpoints para IPs, Hashes, Dominios y URLs generados en los **últimos 30 días**.
3.  **Creación de Eventos**: Genera un único evento diario en MISP, agrupando todos los indicadores.
4.  **Etiquetado**: Aplica tags específicos (p. ej., `CSIRT-Nacional-Chile`, `IOC-IPV4`) al evento y los atributos.
5.  **Notificación**: Envía un resumen por correo electrónico al equipo SOC al finalizar la importación.

## 🛠️ Requisitos

  * **Python 3.x**
  * **Credenciales API:** Acceso válido a la API de ANCI/CSIRT Nacional.
  * **MISP:** Una instancia local de MISP activa con una clave API de usuario con permisos de escritura.

### Dependencias de Python

Instala las bibliotecas requeridas en tu entorno virtual (`venv`):

```bash
pip install requests pymisp
```

## ⬇️ Instalación

1.  Clona el repositorio:
    ```bash
    git clone https://github.com/tu-usuario/tu-repositorio.git
    cd tu-repositorio
    ```
2.  Crea y activa el entorno virtual (opcional pero recomendado):
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  Instala las dependencias (ver sección anterior).

## 🔑 Configuración de Credenciales

**⛔ ¡ATENCIÓN\! No edites directamente el código fuente (`conector_anci.py`) para ingresar credenciales si vas a compartir el código. Utiliza Variables de Entorno.**

### Variables de Entorno (Recomendado)

Configura las siguientes variables en el shell que ejecuta el script (`~/.bashrc`, `~/.zshrc` o en la configuración de tu `cron job`):

| Variable | Descripción | Ejemplo de Valor |
| :--- | :--- | :--- |
| `ANCI_USER` | Usuario de la API de ANCI/CSIRT Nacional.|
| `ANCI_PASS` | Contraseña del usuario ANCI. |
| `MISP_LOCAL_URL` | URL de tu instancia MISP (sin barra al final). |
| `MISP_LOCAL_KEY` | Clave API de tu usuario MISP. |

**Ejemplo de cómo exportar las variables temporalmente:**

```bash
export MISP_LOCAL_URL="https://172.20.10.02"
export MISP_LOCAL_KEY="TU_CLAVE_AQUI"
# ... y las credenciales de ANCI
```

### Configuración de Email

Si `EMAIL_ENABLED` es `True` dentro del script, el conector intentará enviar notificaciones. Asegúrate de configurar los siguientes parámetros en la sección `1c. CONFIGURACION DE EMAIL` del archivo `conector_anci.py` **localmente**:

  * `EMAIL_HOST`
  * `EMAIL_PORT`
  * `EMAIL_USER`
  * `EMAIL_PASSWORD`
  * `EMAIL_RECIPIENTS`

## 🏃 Ejecución

El script está diseñado para ejecutarse en demanda o mediante una tarea programada.

```bash
# 1. Asegúrate de que tu entorno virtual esté activo (si lo usas)
source venv/bin/activate 

# 2. Ejecuta el script
python conector_anci.py
```

### Automatización con Cron

Para la ejecución diaria, configura un `cron job`. El siguiente ejemplo ejecuta el script todos los días a las 09:00 AM. Asegúrate de que las variables de entorno estén disponibles para el `cron` o usa la ruta absoluta:

```bash
# Ejecutar `crontab -e` y añadir:
0 9 * * * /usr/bin/env python3 /ruta/absoluta/a/conector_anci.py >> /var/log/conector_anci.log 2>&1
```

## 📚 Estructura y Mapeo

El conector maneja dos tipos de estructuras de API de ANCI:

1.  **IoCs Simples** (`process_iocs`): Dominios y URLs.
2.  **IoCs Anidados** (`process_nested_iocs`): IPs y Hashes, que vienen agrupados por el nombre de la amenaza (Malware). El script extrae este nombre para usarlo en el campo `Comment` (comentario) del atributo MISP.

| Endpoint (ANCI) | Respuesta JSON Key | Mapeo MISP | Tipo de Procesamiento |
| :--- | :--- | :--- | :--- |
| `/ioc/ip_amenazas` | `amenazas` | `ip-src`, `ip-dst` | Anidado |
| `/ioc/hashes` | `amenazas` | `md5`, `sha1`, `sha256` | Anidado |
| `/ioc/dominios` | `dominios` | `hostname` | Simple |
| `/ioc/urls` | `urls` | `url` | Simple |
