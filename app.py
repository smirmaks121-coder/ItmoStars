from flask import Flask, render_template, jsonify, request, Response
import scanner
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    local_ip = scanner.get_local_ip()
    return render_template('index.html', local_ip=local_ip)

@app.route('/api/scan', methods=['GET'])
def api_scan():
    try:
        scan_data = scanner.scan_network()
        return jsonify({
            "status": "success", 
            "devices": scan_data["devices"],
            "alerts": scan_data["alerts"],
            "first_run": scan_data["first_run"],
            "macs": scan_data["macs"],
            "score": scan_data["score"]
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/save_baseline', methods=['POST'])
def api_save_baseline():
    data = request.get_json()
    if not data or 'macs' not in data:
        return jsonify({"status": "error", "message": "Нет данных"}), 400
    try:
        scanner.save_baseline(data['macs'])
        return jsonify({"status": "success", "message": "Слепок сети успешно зафиксирован в Белом Списке!"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/scan_ports', methods=['POST'])
def api_scan_ports():
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({"status": "error", "message": "Не указан целевой IP"}), 400
    try:
        open_ports = scanner.scan_ports(data['ip'])
        return jsonify({"status": "success", "ports": open_ports})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/export_report', methods=['POST'])
def api_export_report():
    """Генерация красивого интерактивного HTML-отчета."""
    data = request.get_json()
    devices = data.get('devices', [])
    alerts = data.get('alerts', [])
    score = data.get('score', 100)
    
    # Формируем профессиональный HTML-документ
    html = f"""<!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Отчет аудита безопасности домашней сети</title>
        <style>
            body {{ font-family: sans-serif; padding: 40px; background: #f4f6f9; color: #333; }}
            .container {{ max-width: 800px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; border: 1px solid #ddd; }}
            h1 {{ color: #111; border-bottom: 2px solid #111; padding-bottom: 10px; margin-top: 0; }}
            .score-box {{ background: #000; color: #fff; padding: 20px; text-align: center; border-radius: 6px; margin: 20px 0; }}
            .score-val {{ font-size: 48px; font-weight: bold; color: {'#2ed573' if score >= 80 else '#ffa500' if score >= 50 else '#ff4757'}; }}
            .section {{ margin-top: 30px; }}
            .section-title {{ font-weight: bold; font-size: 18px; border-bottom: 1px solid #ccc; padding-bottom: 5px; margin-bottom: 15px; }}
            .alert-item {{ background: #fff5f5; border-left: 4px solid #ff4757; padding: 12px; margin-bottom: 10px; font-size: 14px; }}
            .device-item {{ background: #fafafa; border: 1px solid #eee; padding: 15px; margin-bottom: 10px; border-radius: 4px; font-size: 14px; }}
            .badge {{ display: inline-block; padding: 3px 8px; font-size: 12px; background: #eee; border-radius: 3px; font-weight: bold; }}
            .badge.danger {{ background: #ff4757; color: #fff; }}
            .badge.success {{ background: #2ed573; color: #fff; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Отчет безопасности NetWatcher Pro</h1>
            <p>Проверка завершена успешно. Ниже представлены данные комплексного анализа сетевой инфраструктуры.</p>
            
            <div class="score-box">
                <div class="score-val">{score}%</div>
                <div>Индекс безопасности вашей сети</div>
            </div>
            
            <div class="section">
                <div class="section-title">Анализ угроз и аномалий ({len(alerts)})</div>
    """
    
    if alerts:
        for a in alerts:
            html += f'<div class="alert-item"><strong>[УГРОЗА]</strong> {a["message"]}</div>'
    else:
        html += '<p style="color: #2ed573; font-weight: bold;">✓ Активных сетевых угроз и хакерских вмешательств не обнаружено.</p>'
        
    html += """</div>
            <div class="section">
                <div class="section-title">Зафиксированные сетевые узлы</div>
    """
    
    for d in devices:
        status_badge = '<span class="badge danger">УГРОЗА ПЕРИМЕТРА</span>' if d['status'] == 'rogue' else '<span class="badge success">Разрешено</span>'
        html += f"""
        <div class="device-item">
            <strong>Устройство:</strong> {d['hostname']} {status_badge}<br>
            <strong>IP-Адрес:</strong> {d['ip']}<br>
            <strong>MAC-Адрес:</strong> {d['mac']}<br>
            <strong>Операционная система:</strong> {d['os']}
        </div>
        """
        
    html += """</div>
            <p style="margin-top: 40px; font-size: 12px; color: #777; text-align: center;">Отчет сформирован автоматически модулем NetWatcher Pro.</p>
        </div>
    </body>
    </html>"""
    
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-disposition": "attachment; filename=security_report.html"}
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
