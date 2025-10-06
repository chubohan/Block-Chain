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
    if not getattr(current_user, 'insurance_officer', False):
        return jsonify({'success': False, 'message': '無權限訪問'})
    
    try:
        # 獲取表單數據
        client_gmail = request.form.get('client_gmail')
        policy_number = request.form.get('policy_number')
        insurance_company = request.form.get('insurance_company')
        policy_holder = request.form.get('policy_holder')
        insured_person = request.form.get('insured_person')
        insurance_amount = request.form.get('insurance_amount')
        premium_period = request.form.get('premium_period')
        premium_amount = request.form.get('premium_amount')
        start_date = request.form.get('start_date')
        beneficiary = request.form.get('beneficiary')
        growth_rate = request.form.get('growth_rate')
        declared_interest_rate = request.form.get('declared_interest_rate')
        
        # 驗證必填字段
        if not all([client_gmail, policy_number, insurance_company]):
            return jsonify({'success': False, 'message': '請填寫所有必填字段'})
        
        # 處理文件上傳 - 安全地檢查文件
        pdf_filename = None
        pdf_file = request.files.get('pdf_file')
        
        # 安全地檢查文件是否存在且有文件名
        if pdf_file and hasattr(pdf_file, 'filename') and pdf_file.filename:
            filename = secure_filename(pdf_file.filename)
            # 確保上傳目錄存在
            upload_dir = os.path.join('uploads', 'policies')
            os.makedirs(upload_dir, exist_ok=True)
            
            pdf_path = os.path.join(upload_dir, filename)
            pdf_file.save(pdf_path)
            pdf_filename = filename
            print(f"文件已保存: {pdf_path}")
        else:
            print("沒有上傳文件或文件為空")
        
        # 連接數據庫並插入數據
        conn = db.get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO policy_draft (
                    client_gmail, policy_number, insurance_company, policy_holder,
                    insured_person, insurance_amount, premium_period, premium_amount,
                    start_date, beneficiary, growth_rate, declared_interest_rate,
                    pdf_filename, officer_gmail, status, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                client_gmail, policy_number, insurance_company, policy_holder,
                insured_person, int(insurance_amount) if insurance_amount else 0,
                int(premium_period) if premium_period else 0,
                int(premium_amount) if premium_amount else 0,
                start_date, beneficiary, 
                float(growth_rate) if growth_rate else 0.0,
                float(declared_interest_rate) if declared_interest_rate else 0.0,
                pdf_filename, current_user.id, 0  # status = 0 表示草稿
            ))
            
            conn.commit()
            
        return jsonify({
            'success': True, 
            'message': '保單新增成功',
            'policy_id': cursor.lastrowid
        })
        
    except Exception as e:
        print(f"上傳保單錯誤: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'上傳失敗：{str(e)}'})

@officer_bp.route('/upload-policy-page', methods=['GET'])
@login_required
def upload_policy_page():
    if not getattr(current_user, 'insurance_officer', False):
        return redirect('/')

    client_gmail = request.args.get('client_gmail', '')

    return render_template('officer/upload_form.html', currentUser=current_user, client_gmail=client_gmail)

@officer_bp.route('/client-policies', methods=['GET'])
@login_required
def client_policies():
    if not getattr(current_user, 'insurance_officer', False):
        return redirect('/')
    
    client_gmail = request.args.get('client_gmail')
    if not client_gmail:
        return redirect('/officer/client-page')
    
    conn = db.get_connection()
    client_info = None
    policies = []
    
    try:
        with conn.cursor() as cursor:
            # 獲取客戶基本信息
            cursor.execute("""
                SELECT u.gmail, u.username, u.age, u.gender
                FROM user u
                WHERE u.gmail = %s
            """, (client_gmail,))
            client_info = cursor.fetchone()
            
            # 獲取客戶的所有保單
            cursor.execute("""
                SELECT 
                    id, policy_number, insurance_company, policy_holder,
                    insured_person, insurance_amount, premium_period,
                    premium_amount, start_date, beneficiary, growth_rate,
                    declared_interest_rate, pdf_filename, status, created_at
                FROM policy_draft 
                WHERE client_gmail = %s AND officer_gmail = %s
                ORDER BY created_at DESC
            """, (client_gmail, current_user.id))
            policies = cursor.fetchall()
            
    finally:
        conn.close()
    
    return render_template('officer/client_policies.html', 
                         currentUser=current_user,
                         client=client_info,
                         policies=policies)

@officer_bp.route('/view-policy', methods=['GET'])
@login_required
def view_policy():
    if not getattr(current_user, 'insurance_officer', False):
        return redirect('/')
    
    policy_id = request.args.get('policy_id')
    if not policy_id:
        return redirect('/officer/client-page')
    
    conn = db.get_connection()
    policy = None
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    pd.*,
                    u.username as client_name
                FROM policy_draft pd
                JOIN user u ON pd.client_gmail = u.gmail
                WHERE pd.id = %s AND pd.officer_gmail = %s
            """, (policy_id, current_user.id))
            policy = cursor.fetchone()
    finally:
        conn.close()
    
    if not policy:
        return redirect('/officer/client-page')
    
    return render_template('officer/view_policy.html', 
                         currentUser=current_user,
                         policy=policy)

@officer_bp.route('/get-policy-data', methods=['GET'])
@login_required
def get_policy_data():
    """獲取保單數據用於編輯"""
    if not getattr(current_user, 'insurance_officer', False):
        return jsonify({'success': False, 'message': '無權限訪問'})
    
    policy_id = request.args.get('policy_id')
    if not policy_id:
        return jsonify({'success': False, 'message': '缺少保單ID'})
    
    conn = db.get_connection()
    policy = None
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT * FROM policy_draft 
                WHERE id = %s AND officer_gmail = %s
            """, (policy_id, current_user.id))
            policy = cursor.fetchone()
    finally:
        conn.close()
    
    if not policy:
        return jsonify({'success': False, 'message': '保單不存在'})
    
    # 轉換日期格式
    policy_data = {
        'id': policy['id'],
        'client_gmail': policy['client_gmail'],
        'policy_number': policy['policy_number'],
        'insurance_company': policy['insurance_company'],
        'policy_holder': policy['policy_holder'],
        'insured_person': policy['insured_person'],
        'insurance_amount': policy['insurance_amount'],
        'premium_period': policy['premium_period'],
        'premium_amount': policy['premium_amount'],
        'start_date': policy['start_date'].strftime('%Y-%m-%d') if policy['start_date'] else None,
        'beneficiary': policy['beneficiary'],
        'growth_rate': policy['growth_rate'],
        'declared_interest_rate': policy['declared_interest_rate'],
        'pdf_filename': policy['pdf_filename'],
        'status': policy['status']
    }
    
    return jsonify({'success': True, 'policy': policy_data})
@officer_bp.route('/update-policy', methods=['POST'])
@login_required
def update_policy():
    if not getattr(current_user, 'insurance_officer', False):
        return jsonify({'success': False, 'message': '無權限訪問'})
    
    policy_id = request.form.get('policy_id')
    if not policy_id:
        return jsonify({'success': False, 'message': '缺少保單ID'})
    
    print("=== 接收到的表單數據 ===")
    for key in request.form:
        print(f"'{key}': '{request.form[key]}'")
    
    conn = db.get_connection()
    
    try:
        with conn.cursor() as cursor:
            # 直接更新所有字段，不處理文件
            update_fields = []
            update_values = []
            
            # 定義所有可能更新的字段
            fields_to_update = [
                ('client_gmail', 'str'),
                ('policy_number', 'str'),
                ('insurance_company', 'str'),
                ('policy_holder', 'str'),
                ('insured_person', 'str'),
                ('insurance_amount', 'int'),
                ('premium_period', 'int'),
                ('premium_amount', 'int'),
                ('start_date', 'str'),
                ('beneficiary', 'str'),
                ('growth_rate', 'float'),
                ('declared_interest_rate', 'float')
            ]
            
            for field_name, field_type in fields_to_update:
                value = request.form.get(field_name)
                if value is not None and value != '':
                    update_fields.append(f"{field_name} = %s")
                    
                    if field_type == 'int':
                        try:
                            update_values.append(int(value))
                        except:
                            update_values.append(0)
                    elif field_type == 'float':
                        try:
                            update_values.append(float(value))
                        except:
                            update_values.append(0.0)
                    else:
                        update_values.append(value)
                    print(f"添加字段 {field_name}: {value}")
            
            if update_fields:
                update_values.extend([policy_id, current_user.id])
                
                query = f"UPDATE policy_draft SET {', '.join(update_fields)} WHERE id = %s AND officer_gmail = %s"
                print("執行 SQL:", query)
                print("參數:", update_values)
                
                cursor.execute(query, update_values)
                conn.commit()
                
                return jsonify({'success': True, 'message': '保單更新成功'})
            else:
                return jsonify({'success': False, 'message': '沒有提供更新數據'})
            
    except Exception as e:
        conn.rollback()
        print(f"更新錯誤: {str(e)}")
        return jsonify({'success': False, 'message': f'更新失敗：{str(e)}'})
    finally:
        conn.close()