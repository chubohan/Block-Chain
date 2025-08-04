from flask import Blueprint, request, jsonify, render_template, redirect
from flask_login import login_required, current_user
from utils import db, ipfs

officer_bp = Blueprint('officer', __name__, url_prefix='/officer')

@officer_bp.route('/client-page', methods=['GET'])
@login_required
def client_page():
    if not getattr(current_user, 'insurance_officer', False):
        return redirect('/')

    conn = db.get_connection()
    clients = []
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT u.gmail, u.username, u.age, u.gender, u.created_at
                FROM insurance_officer_clients c
                JOIN user u ON c.client_gmail = u.gmail
                WHERE c.officer_gmail = %s
            """, (current_user.id,))
            clients = cursor.fetchall()
    finally:
        conn.close()

    return render_template('officer/customer.html', currentUser=current_user, clients=clients)

@officer_bp.route('/link-client', methods=['POST'])
@login_required
def link_client():
    if not getattr(current_user, 'insurance_officer', False):
        return jsonify({'success': False, 'message': '無權限訪問此功能'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': '無效的請求數據'}), 400

    client_gmail = data.get('client_gmail')
    if not client_gmail:
        return jsonify({'success': False, 'message': '請輸入客戶Gmail'}), 400

    try:
        conn = db.get_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM user WHERE gmail = %s", (client_gmail,))
            client = cursor.fetchone()

            if not client:
                return jsonify({'success': False, 'message': '該gmail未註冊'}), 404

            if client.get('insurance_officer', 0) == 1:
                return jsonify({'success': False, 'message': '該gmail不是客戶'}), 400

            cursor.execute("""
                SELECT * FROM insurance_officer_clients 
                WHERE officer_gmail = %s AND client_gmail = %s
            """, (current_user.id, client_gmail))

            if cursor.fetchone():
                return jsonify({'success': False, 'message': '該客戶已是您的客戶'}), 400

            cursor.execute("""
                INSERT INTO insurance_officer_clients (officer_gmail, client_gmail, linked_at)
                VALUES (%s, %s, NOW())
            """, (current_user.id, client_gmail))
            conn.commit()

            return jsonify({
                'success': True,
                'client': {
                    'gmail': client['gmail'],
                    'username': client['username'],
                    'age': client['age'],
                    'gender': client['gender']
                }
            })
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({'success': False, 'message': f'伺服器錯誤: {str(e)}'}), 500
    finally:
        if conn:
            conn.close()
@officer_bp.route('/get-clients', methods=['GET'])
@login_required
def get_clients():
    if not getattr(current_user, 'insurance_officer', False):
        return jsonify({'success': False, 'message': '無權限訪問此功能'}), 403

    conn = db.get_connection()
    clients = []
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT u.gmail, u.username, u.age, u.gender, u.created_at
                FROM insurance_officer_clients c
                JOIN user u ON c.client_gmail = u.gmail
                WHERE c.officer_gmail = %s
            """, (current_user.id,))
            clients = cursor.fetchall()
    finally:
        conn.close()

    return jsonify({'success': True, 'clients': clients})
@officer_bp.route('/delete-client', methods=['POST'])
@login_required
def delete_client():
    if not getattr(current_user, 'insurance_officer', False):
        return jsonify({'success': False, 'message': '無權限操作'}), 403

    data = request.get_json()
    client_gmail = data.get('client_gmail')

    if not client_gmail:
        return jsonify({'success': False, 'message': '缺少客戶Gmail'}), 400

    try:
        conn = db.get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                DELETE FROM insurance_officer_clients 
                WHERE officer_gmail = %s AND client_gmail = %s
            """, (current_user.id, client_gmail))
            conn.commit()
            return jsonify({'success': True})
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

import os
from flask import current_app
from werkzeug.utils import secure_filename
from datetime import datetime
from utils.ipfs import upload_to_pinata

@officer_bp.route('/upload-policy', methods=['POST'])
@login_required
def upload_policy():
    conn=None

    if not getattr(current_user, 'insurance_officer', False):
        return jsonify({'success': False, 'message': '無權限操作'}), 403

    try:
        # 取得表單資料
        client_gmail = request.form.get('clientGmail')
        policy_number = request.form.get('policyNumber')
        insurance_company = request.form.get('insuranceCompany')
        policy_holder = request.form.get('policyHolder')
        insured_person = request.form.get('insuredPerson')
        insurance_amount = request.form.get('insuranceAmount')
        premium_period = request.form.get('premiumPeriod')
        premium_amount = request.form.get('premiumAmount')
        start_date = request.form.get('startDate')
        beneficiary = request.form.get('beneficiary')
        growth_rate = request.form.get('growthRate')
        declared_interest_rate = request.form.get('declaredInterestRate')
        pdf_file = request.files.get('pdfUpload')
        ipfs_hash = request.form.get('ipfsHash')

        if not all([...]):
            return jsonify({'success': False, 'message': '所有欄位皆為必填'}), 400

        # 儲存到暫存路徑以便上傳至 Pinata
        filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{pdf_file.filename}")
        upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        pdf_file.save(upload_path)

        # 上傳至 Pinata 並取得 IPFS hash
        pdf_hash = ipfs_hash
        print("儲存的檔名為：", filename)
        # 寫入 policy_draft
        conn = db.get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO policy_draft (
                    client_gmail, policy_number, insurance_company, policy_holder, insured_person,
                    insurance_amount, premium_period, premium_amount, start_date,
                    beneficiary, growth_rate, declared_interest_rate,
                    pdf_filename, pdf_hash, officer_gmail
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                client_gmail, policy_number, insurance_company, policy_holder, insured_person,
                insurance_amount, premium_period, premium_amount, start_date,
                beneficiary, growth_rate, declared_interest_rate,
                filename, pdf_hash, current_user.id
            ))
            conn.commit()

        return jsonify({'success': True, 'ipfs_hash': pdf_hash})
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@officer_bp.route('/upload-policy-page', methods=['GET'])
@login_required
def upload_policy_page():
    if not getattr(current_user, 'insurance_officer', False):
        return redirect('/')

    client_gmail = request.args.get('client_gmail', '')

    return render_template('officer/upload_form.html', currentUser=current_user, client_gmail=client_gmail)
