import json
import base64
import config
from flask import Flask, request, jsonify
from decrypt_response import decrypt
app = Flask(__name__)


@app.route('/kb/registration', methods=['POST'])
def registration():
    state = request.args.get("state")
    data = request.get_json()
    data['encryptionKey'] = config.KEY
    data['redirectUris'] = f"{config.URL}/kb/callback"
    data = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
    url = f"https://api.kb.cz/client-registration/saml/register?registrationRequest={data}&state={state}"
    return jsonify({'message': 'Data received in endpoint1', 'received_data': data}), 200


@app.route('/kb/callback', methods=['GET'])
def decode():
    salt = request.args.get("salt")
    encrypted_data = request.args.get('encryptedData')
    data = decrypt(salt, encrypted_data)
    return jsonify(json.loads(data)), 200


if __name__ == '__main__':
    app.run(debug=True)
