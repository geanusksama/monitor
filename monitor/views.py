import requests
from datetime import datetime, timedelta, timezone
import psycopg2
from psycopg2 import sql
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import pytz

# Configurações do Banco de Dados
DB_HOST = 'aws-0-us-east-1.pooler.supabase.com'
DB_PORT = 6543
DB_NAME = 'postgres'
DB_USER = 'postgres.uoswswovjcycsamjawnl'
DB_PASSWORD = 'Manaus@92Master'


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


LOGIN_BODY = {
    "login": "admin",
    "password": "admin"
}
HEADERS = {"Content-Type": "application/json"}


def get_session(ip_cliente):
    login_url = f"http://{ip_cliente}/login.fcgi"
    try:
        response = requests.post(login_url, json=LOGIN_BODY, headers=HEADERS, timeout=5)
        if response.status_code == 200:
            return response.json().get("session")
    except requests.exceptions.RequestException as e:
        print(f"Erro ao obter sessão: {e}")
    return None


def get_access_logs(ip_cliente):
    session_id = get_session(ip_cliente)
    if not session_id:
        return []

    sao_paulo_tz = pytz.timezone('America/Sao_Paulo')
    now = datetime.now(sao_paulo_tz)
    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = start_of_day + timedelta(days=1)
    start_timestamp = int(start_of_day.timestamp())
    end_timestamp = int(end_of_day.timestamp())

    url = f"http://{ip_cliente}/load_objects.fcgi?session={session_id}"
    body = {
        "object": "access_logs",
        "where": [
            {"object": "access_logs", "field": "time", "operator": ">", "value": start_timestamp, "connector": ") AND ("},
            {"object": "access_logs", "field": "time", "operator": "<", "value": end_timestamp}
        ]
    }
    try:
        response = requests.post(url, json=body, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            return response.json().get('access_logs', [])
    except requests.exceptions.RequestException as e:
        print(f"Erro ao buscar access_logs: {e}")
    return []


def get_user_data(user_id, ip_cliente):
    session_id = get_session(ip_cliente)
    if not session_id:
        return {}

    url = f"http://{ip_cliente}/load_objects.fcgi?session={session_id}"
    body = {"object": "users", "where": {"users": {"id": user_id}}}

    try:
        response = requests.post(url, json=body, headers=HEADERS, timeout=5)
        if response.status_code == 200:
            users = response.json().get('users', [])
            return users[0] if users else {}
    except requests.exceptions.RequestException as e:
        print(f"Erro ao buscar user_data: {e}")
    return {}


def save_to_db(data):
    try:
        connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = connection.cursor()

        if data:
            entry = data[-1]
            try:
                timestamp = int(entry['datahora'])
                datahora_utc = datetime.fromtimestamp(timestamp, pytz.UTC)
                datahora = datahora_utc.astimezone(pytz.timezone('America/Sao_Paulo'))

                sql_query = """
                INSERT INTO tbpresenca (
                    nome, device, created_at, logid, event, confidence, rol, tipo, cpf, stringunica, datahora
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                values = (
                    entry['nome'], entry['device'], datetime.utcnow(), entry['logid'],
                    entry['event'], entry['confidence'], entry['rol'], entry['tipo'],
                    entry['cpf'], entry['stringunica'], datahora
                )
                cursor.execute(sql_query, values)
                connection.commit()
            except Exception as e:
                print(f"Erro ao salvar no banco: {e}")
                connection.rollback()

        cursor.close()
        connection.close()

    except psycopg2.Error as e:
        print(f"Erro de conexão com o banco: {e}")


def get_setor(device_id, ip_cliente):
    try:
        connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = connection.cursor()

        cursor.execute("""
            SELECT setor FROM tbdispositivo WHERE CAST(idface AS bigint) = %s
        """, (str(device_id),))

        setor = cursor.fetchone()
        return setor[0] + 'TRUE' if setor else 'N/A'

    except Exception as e:
        print(f"Erro ao buscar setor: {e}")
        return 'N/A'
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@csrf_exempt
@require_POST
def dao_notifications(request):
    ip_cliente = get_client_ip(request)
    print('IP cliente', ip_cliente)

    access_logs = get_access_logs(ip_cliente)

    if access_logs:
        log = access_logs[-1]
        setor = get_setor(log.get('device_id', 'N/A'), ip_cliente)
        user_data = get_user_data(log['user_id'], ip_cliente)

        combined_data = [{
            'id': log['id'],
            'nome': user_data.get('name', 'N/A'),
            'device': log.get('device_id', 'N/A'),
            'logid': log['id'],
            'event': log.get('event', 0),
            'confidence': log.get('confidence', 0),
            'rol': user_data.get('registration', 0),
            'tipo': setor,
            'cpf': log['user_id'],
            'stringunica': f"{log.get('device_id', 'N/A')}{setor}",
            'datahora': log.get('time', 0)
        }]

        save_to_db(combined_data)

        return JsonResponse({"status": "success", "data": combined_data[-1]})
    else:
        return JsonResponse({"status": "success", "message": "Nenhum log recuperado."})


@csrf_exempt
@require_POST
def secbox_notifications(request):
    return JsonResponse({"status": "success", "message": "secbox_notifications endpoint called"})
