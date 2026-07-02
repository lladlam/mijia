import argparse
import json
import tempfile
from pathlib import Path
from urllib.parse import parse_qs

from mijiaAPI import decrypt


SENSITIVE_EXPORT_KEYS = {
    "_nonce",
    "nonce",
    "ssecurity",
    "serviceToken",
    "yetAnotherServiceToken",
    "passToken",
    "userId",
    "cUserId",
}


def parse_args():
    parser = argparse.ArgumentParser(description='解密米家APP中的请求与响应数据')
    parser.add_argument('-p', '--har_path', required=True, help='HAR 文件路径')
    return parser.parse_args()


def _redact_secret(value):
    text = str(value)
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:2]}***{text[-2:]}"


def redact_sensitive_data(value):
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if key in SENSITIVE_EXPORT_KEYS:
                redacted[key] = _redact_secret(item)
            else:
                redacted[key] = redact_sensitive_data(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    return value


def sanitize_json_text(text):
    try:
        return redact_sensitive_data(json.loads(text))
    except json.JSONDecodeError:
        return text

def decrypt_request(request):
    request_data = request.get('postData', {}).get('text', '')
    if not request_data:
        return None, None, None
    request_data = parse_qs(request_data)
    request_data = {k: v[0] for k, v in request_data.items() if isinstance(v, list) and len(v) == 1}
    nonce = request_data.get('_nonce')
    ssecurity = request_data.get('ssecurity')
    data = request_data.get('data')
    if not nonce or not ssecurity or not data:
        return None, nonce, ssecurity
    decrypted_data = decrypt(ssecurity, nonce, data)
    return decrypted_data, nonce, ssecurity

def decrypt_response(response, nonce, ssecurity):
    response_body = response.get('content', {}).get('text', '')
    if not response_body:
        return None
    if not nonce or not ssecurity:
        return None
    decrypted_response = decrypt(ssecurity, nonce, response_body)
    return decrypted_response

def simplify_har(har_data):
    data = []
    for entry in har_data['log']['entries']:
        if entry.get('request', {}).get('method') != 'POST':
            continue
        request_url = entry.get('request', {}).get('url')
        request_method = entry.get('request', {}).get('method')
        request_data = entry.get('request', {}).get('postData', {})
        if 'text' in request_data and isinstance(request_data['text'], str):
            request_data['text'] = sanitize_json_text(request_data['text'])
        response_status = entry.get('response', {}).get('status')
        response_content = entry.get('response', {}).get('content', {})
        if 'text' in response_content and isinstance(response_content['text'], str):
            response_content['text'] = sanitize_json_text(response_content['text'])
        started_date = entry.get('startedDateTime')
        latency = entry.get('time', 0)

        data.append({
            'request': {
                'url': request_url,
                'method': request_method,
                'postData': request_data,
            },
            'response': {
                'status': response_status,
                'content': response_content,
            },
            'startedDateTime': started_date,
            'time': latency,
        })
    return data

def update_headers(headers, content_length):
    for header in headers:
        if header['name'].lower() == 'content-type':
            header['value'] = 'application/json'
        elif header['name'].lower() == 'content-length':
            header['value'] = str(content_length)
    return headers

if __name__ == "__main__":
    args = parse_args()
    har_path = Path(args.har_path)
    with open(har_path, 'r', encoding='utf-8') as f:
        har_data = json.load(f)
    entries = []
    for entry in har_data['log']['entries']:
        request = entry['request']
        if request['method'] != 'POST':
            entries.append(entry)
            continue

        decrypted_data, nonce, ssecurity = decrypt_request(request)
        if decrypted_data:
            entry['request']['postData']['text'] = sanitize_json_text(decrypted_data)
            entry['request']['postData']['mimeType'] = 'application/json'
            serialized_request = json.dumps(entry['request']['postData']['text'], ensure_ascii=False)
            entry['request']['headers'] = update_headers(entry['request'].get('headers', []), len(serialized_request))

        decrypted_response = decrypt_response(entry.get('response', {}), nonce, ssecurity)
        if decrypted_response:
            entry['response']['content']['text'] = sanitize_json_text(decrypted_response)
            entry['response']['content']['mimeType'] = 'application/json'
            serialized_response = json.dumps(entry['response']['content']['text'], ensure_ascii=False)
            entry['response']['headers'] = update_headers(entry['response'].get('headers', []), len(serialized_response))
        entries.append(entry)
    har_data['log']['entries'] = entries
    output_dir = Path(tempfile.gettempdir()) / "mijia-api-decrypt"
    output_dir.mkdir(parents=True, exist_ok=True)
    decrypted_path = output_dir / f"{har_path.stem}_decrypted.har"
    with open(decrypted_path, 'w', encoding='utf-8') as f:
        json.dump(har_data, f, ensure_ascii=False, indent=2)
    print(f'已保存解密的HAR文件: {decrypted_path}')
    simplified_path = output_dir / f"{har_path.stem}_decrypted_simplified.json"
    with open(simplified_path, 'w', encoding='utf-8') as f:
        json.dump(simplify_har(har_data), f, ensure_ascii=False, indent=2)
    print(f'已保存简化后的JSON文件: {simplified_path}')
