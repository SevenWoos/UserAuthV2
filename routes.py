from flask import render_template, request, redirect, url_for, session, jsonify,Blueprint
from flask_login import login_required, current_user
import requests

chat_bp = Blueprint('chat', __name__)

@chat_bp.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        user_input = request.json['message']

        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                "model": "llama3",  # or whichever model you're running
                "prompt": user_input,
                "stream": False
            }
        )
        data = response.json()
        return jsonify({"response": data.get("response", "")})

    return render_template('chat.html', user=current_user)