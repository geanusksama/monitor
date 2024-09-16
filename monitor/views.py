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

# URL e credenciais para login
LOGIN_URL = "http://192.168.0.129/login.fcgi"
LOGIN_BODY = {
    "login": "admin",
    "password": "admin"
}
HEADERS = {"Content-Type": "application/json"}

def get_session():
    response = requests.post(LOGIN_URL, json=LOGIN_BODY, headers=HEADERS)
    if response.status_code == 200:
        session_id = response.json().get("session")
        if session_id:
            return session_id
    print(f"Falha ao obter a sessão, status code: {response.status_code}")
    return None

def get_access_logs():
    session_id = get_session()
    if not session_id:
        print("Sessão inválida ou não obtida.")
        return []

    sao_paulo_tz = pytz.timezone('America/Sao_Paulo')
    now = datetime.now(sao_paulo_tz)
    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = start_of_day + timedelta(days=1)
    start_timestamp = int(start_of_day.timestamp())
    end_timestamp = int(end_of_day.timestamp())

    url = f"http://192.168.0.129/load_objects.fcgi?session={session_id}"
    body = {
        "object": "access_logs",
        "where": [
            {"object": "access_logs", "field": "time", "operator": ">", "value": start_timestamp, "connector": ") AND ("},
            {"object": "access_logs", "field": "time", "operator": "<", "value": end_timestamp}
        ]
    }
    response = requests.post(url, json=body, headers=HEADERS)

    print("Status da resposta:", response.status_code)
    print("Conteúdo da resposta:", response.text)

    if response.status_code == 200:
        return response.json().get('access_logs', [])
    else:
        print(f"Falha ao recuperar os logs de acesso, status code: {response.status_code}")
        return []

def get_user_data(user_id):
    session_id = get_session()
    if not session_id:
        print("Sessão inválida ou não obtida.")
        return {}

    url = f"http://192.168.0.129/load_objects.fcgi?session={session_id}"
    body = {"object": "users", "where": {"users": {"id": user_id}}}
    response = requests.post(url, json=body, headers=HEADERS)

    print("Status da resposta:", response.status_code)
    print("Conteúdo da resposta:", response.text)

    if response.status_code == 200:
        user_data = response.json().get('users', [])
        return user_data[0] if user_data else {}
    else:
        print(f"Falha ao recuperar os dados do usuário, status code: {response.status_code}")
        return {}

def save_to_db(data):
    try:
        # Conectar ao banco de dados
        connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = connection.cursor()

        if data:
            # Obter o último registro da lista
            entry = data[-1]  # Apenas o último registro

            try:
                # Corrigir a conversão do timestamp Unix para datetime, considerando o fuso horário de São Paulo
                if entry['datahora']:
                    timestamp = int(entry['datahora'])
                    # Converter o timestamp Unix para datetime no UTC
                    datahora_utc = datetime.fromtimestamp(timestamp, pytz.UTC)
                    # Converter para o horário de São Paulo
                    sao_paulo_tz = pytz.timezone('America/Sao_Paulo')
                    datahora = datahora_utc.astimezone(sao_paulo_tz)
                else:
                    datahora = None

                # Inserir dados na tabela tbpresenca
                sql_query = """
                INSERT INTO tbpresenca (
                    nome, device, created_at, logid, event, confidence, rol, datahora
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
                values = (
                    entry['nome'],
                    entry['device'],
                    datetime.utcnow(),  # timestamp da inserção
                    entry['logid'],
                    entry['event'],
                    entry['confidence'],
                    entry['rol'],
                    datahora  # Corrigido para o timestamp convertido
                )
                cursor.execute(sql_query, values)
                connection.commit()
                print(f"Último registro salvo: {values}")
            except psycopg2.Error as e:
                print(f"Erro ao inserir registro: {e}")
                connection.rollback()

        cursor.close()
        connection.close()

    except psycopg2.Error as e:
        print(f"Erro na conexão com o banco de dados: {e}")

@csrf_exempt
@require_POST
def dao_notifications(request):
    access_logs = get_access_logs()
    combined_data = []

    for log in access_logs:
        user_data = get_user_data(log['user_id'])
        combined_data.append({
            'id': log['id'],
            'nome': user_data.get('name', 'N/A'),
            'device': log.get('device_id', 'N/A'),
            'logid': log['id'],
            'event': log.get('event', 0),  # Definindo valor padrão como 0
            'confidence': log.get('confidence', 0),  # Definindo valor padrão como 0
            'rol': user_data.get('registration', 0),  # Definindo valor padrão como 0
            'datahora': log.get('time', 0)  # Corrigido para usar o timestamp Unix correto
        })

    if combined_data:
        save_to_db(combined_data)
        return JsonResponse({"status": "success", "data": combined_data[-1]})  # Retornar apenas o último registro
    else:
        return JsonResponse({"status": "success", "message": "Nenhum log recuperado."})

@csrf_exempt
@require_POST
def secbox_notifications(request):
    return JsonResponse({"status": "success", "message": "secbox_notifications endpoint called"})
