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
#刪除客戶
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
@officer_bp.route('/delete_policy/<policy_number>', methods=['POST'])
@login_required
def delete_policy(policy_number):  # 參數名稱改為 policy_number
    user_email = current_user.id
    
    conn = None
    try:
        conn = db.get_connection()
        cursor = conn.cursor()

        print(f"開始處理保單: {policy_number}, 用戶: {user_email}")

        # 檢查保單是否存在且屬於當前用戶
        cursor.execute("""
            SELECT policy_id, client_gmail 
            FROM policy 
            WHERE policy_id = %s AND client_gmail = %s
        """, (policy_number, user_email))
        
        policy = cursor.fetchone()
        
        if not policy:
            return jsonify({'success': False, 'message': '保單不存在或您沒有權限刪除'})

        # 在同一個 transaction 中處理三個資料表的記錄
        # 先刪除 authorization 表中的相關授權記錄
        cursor.execute("""
            DELETE FROM authorization 
            WHERE policy_number = %s
        """, (policy_number,))
        auth_deleted = cursor.rowcount

        # 修改：將 policy_draft 的 status 更新為 2 而不是刪除
        cursor.execute("""
            UPDATE policy_draft 
            SET status = 2 
            WHERE client_gmail = %s AND policy_number = %s
        """, (user_email, policy_number))
        draft_updated = cursor.rowcount

        # 刪除 policy
        cursor.execute("""
            DELETE FROM policy 
            WHERE client_gmail = %s AND policy_id = %s
        """, (user_email, policy_number))
        policy_deleted = cursor.rowcount

        conn.commit()
        
        print(f"處理結果 - 授權表: {auth_deleted} 條, 草稿表: {draft_updated} 條更新, 政策表: {policy_deleted} 條")
        
        return jsonify({
            'success': True, 
            'message': f'保單及相關授權處理成功！',
            'details': {
                'auth_deleted': auth_deleted,
                'draft_updated': draft_updated,
                'policy_deleted': policy_deleted
            }
        })
                
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"處理保單錯誤: {str(e)}")
        return jsonify({'success': False, 'message': f'處理過程中發生錯誤: {str(e)}'})
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
        ipfs_hash = request.form.get('ipfs_hash')  # 新增 IPFS hash
        
        print("=== 接收到的表單數據 ===")
        print(f"client_gmail: {client_gmail}")
        print(f"policy_number: {policy_number}")
        print(f"insurance_company: {insurance_company}")
        print(f"ipfs_hash: {ipfs_hash}")
        
        # 驗證必填字段
        required_fields = {
            'client_gmail': client_gmail,
            'policy_number': policy_number,
            'insurance_company': insurance_company,
            'policy_holder': policy_holder,
            'insured_person': insured_person,
            'insurance_amount': insurance_amount,
            'premium_period': premium_period,
            'premium_amount': premium_amount,
            'start_date': start_date,
            'beneficiary': beneficiary
        }
        
        missing_fields = []
        for field_name, field_value in required_fields.items():
            if not field_value or field_value.strip() == '':
                missing_fields.append(field_name)
        
        if missing_fields:
            return jsonify({
                'success': False, 
                'message': f'缺少必填字段: {", ".join(missing_fields)}'
            })
        
        # 處理文件上傳
        pdf_filename = None
        pdf_file = request.files.get('pdf_file')
        
        if pdf_file and hasattr(pdf_file, 'filename') and pdf_file.filename:
            filename = secure_filename(pdf_file.filename)
            upload_dir = os.path.join('uploads', 'policies')
            os.makedirs(upload_dir, exist_ok=True)
            pdf_path = os.path.join(upload_dir, filename)
            pdf_file.save(pdf_path)
            pdf_filename = filename
            print(f"文件已保存: {pdf_path}")
        else:
            return jsonify({'success': False, 'message': '請上傳 PDF 文件'})
        
        # 類型轉換和默認值處理
        try:
            insurance_amount_int = int(insurance_amount) if insurance_amount else 0
            premium_period_int = int(premium_period) if premium_period else 0
            premium_amount_int = int(premium_amount) if premium_amount else 0
            growth_rate_float = float(growth_rate) if growth_rate else 0.0
            declared_interest_rate_float = float(declared_interest_rate) if declared_interest_rate else 0.0
        except (ValueError, TypeError) as e:
            return jsonify({'success': False, 'message': f'數字格式錯誤: {str(e)}'})
        
        # 連接數據庫並插入數據
        conn = db.get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO policy_draft (
                    client_gmail, policy_number, insurance_company, policy_holder,
                    insured_person, insurance_amount, premium_period, premium_amount,
                    start_date, beneficiary, growth_rate, declared_interest_rate,
                    pdf_filename, officer_gmail, status, created_at, pdf_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)
            """, (
                client_gmail, policy_number, insurance_company, policy_holder,
                insured_person, insurance_amount_int, premium_period_int, premium_amount_int,
                start_date, beneficiary, growth_rate_float, declared_interest_rate_float,
                pdf_filename, current_user.id, 0, ipfs_hash  # status = 0 表示草稿
            ))
            
            conn.commit()
            policy_id = cursor.lastrowid
            
        return jsonify({
            'success': True, 
            'message': '保單新增成功',
            'policy_id': policy_id
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
    
    # 詳細的調試信息
    print("=== 更新保單調試信息 ===")
    policy_id = request.form.get('policy_id')
    print(f"收到的 policy_id: '{policy_id}'")
    
    if not policy_id:
        print("錯誤：policy_id 為空或不存在")
        return jsonify({'success': False, 'message': '缺少保單ID'})
    
    # 調試：打印所有接收到的表單數據
    print("=== 所有接收到的表單數據 ===")
    for key in request.form:
        print(f"'{key}': '{request.form[key]}'")
    
    conn = db.get_connection()
    
    try:
        with conn.cursor() as cursor:
            # 檢查保單是否存在
            cursor.execute("SELECT * FROM policy_draft WHERE id = %s AND officer_gmail = %s", 
                         (policy_id, current_user.id))
            existing_policy = cursor.fetchone()
            
            if not existing_policy:
                print(f"錯誤：保單不存在，policy_id: {policy_id}, officer_gmail: {current_user.id}")
                return jsonify({'success': False, 'message': '保單不存在'})
            
            print("現有保單數據:", existing_policy)
            
            # 使用正確的數據庫字段名稱
            update_fields = []
            update_values = []
            
            # 字段映射
            field_mappings = {
                'client_gmail': 'client_gmail',
                'policy_number': 'policy_number', 
                'insurance_company': 'insurance_company',
                'policy_holder': 'policy_holder',
                'insured_person': 'insured_person', 
                'insurance_amount': 'insurance_amount',
                'premium_period': 'premium_period',
                'premium_amount': 'premium_amount',
                'start_date': 'start_date',
                'beneficiary': 'beneficiary',
                'growth_rate': 'growth_rate',
                'declared_interest_rate': 'declared_interest_rate'
            }
            
            for form_field, db_field in field_mappings.items():
                value = request.form.get(form_field)
                print(f"處理字段: {form_field} -> {db_field}, 值: {value}")
                
                if value is not None and value != '':
                    update_fields.append(f"{db_field} = %s")
                    
                    # 類型轉換
                    if db_field in ['insurance_amount', 'premium_amount', 'premium_period']:
                        try:
                            update_values.append(int(value))
                        except (ValueError, TypeError):
                            update_values.append(0)
                    elif db_field in ['growth_rate', 'declared_interest_rate']:
                        try:
                            update_values.append(float(value))
                        except (ValueError, TypeError):
                            update_values.append(0.0)
                    elif db_field == 'start_date':
                        update_values.append(value)
                    else:
                        update_values.append(value)
            
            # 處理文件上傳和 IPFS hash
            pdf_file = request.files.get('pdf_file')
            ipfs_hash = request.form.get('ipfs_hash')
            
            if pdf_file and pdf_file.filename:
                filename = secure_filename(pdf_file.filename)
                upload_dir = os.path.join('uploads', 'policies')
                os.makedirs(upload_dir, exist_ok=True)
                pdf_path = os.path.join(upload_dir, filename)
                pdf_file.save(pdf_path)
                update_fields.append("pdf_filename = %s")
                update_values.append(filename)
                print(f"文件已保存: {filename}")
            
            # 如果有新的 IPFS hash，更新它
            if ipfs_hash and ipfs_hash.strip():
                update_fields.append("pdf_hash = %s")
                update_values.append(ipfs_hash.strip())
                print(f"更新 IPFS hash: {ipfs_hash}")
            
            print("更新字段:", update_fields)
            print("更新值:", update_values)
            
            if update_fields:
                update_values.extend([policy_id, current_user.id])
                
                query = f"UPDATE policy_draft SET {', '.join(update_fields)} WHERE id = %s AND officer_gmail = %s"
                print("最終 SQL:", query)
                print("最終參數:", update_values)
                
                cursor.execute(query, update_values)
                conn.commit()
                
                # 檢查受影響的行數
                affected_rows = cursor.rowcount
                print(f"受影響的行數: {affected_rows}")
                
                if affected_rows > 0:
                    return jsonify({'success': True, 'message': '保單更新成功'})
                else:
                    return jsonify({'success': False, 'message': '沒有數據被更新'})
            else:
                return jsonify({'success': False, 'message': '沒有提供更新數據'})
            
    except Exception as e:
        conn.rollback()
        print(f"更新錯誤: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'更新失敗：{str(e)}'})
    finally:
        conn.close()

#保險員確認刪除保單
@officer_bp.route('/delete-policy-draft/<int:policy_id>', methods=['POST'])
@login_required
def delete_policy_draft(policy_id):
    """刪除指定的保單草稿"""
    if not getattr(current_user, 'insurance_officer', False):
        return jsonify({'success': False, 'message': '無權限訪問'})
    
    conn = None
    try:
        conn = db.get_connection()
        cursor = conn.cursor()

        # 檢查保單是否存在且屬於當前保險員
        cursor.execute("""
            SELECT id, policy_number, status, client_gmail 
            FROM policy_draft 
            WHERE id = %s AND officer_gmail = %s
        """, (policy_id, current_user.id))
        
        policy = cursor.fetchone()
        
        if not policy:
            return jsonify({'success': False, 'message': '保單不存在或您沒有權限刪除'})

        # 刪除保單草稿
        cursor.execute("""
            DELETE FROM policy_draft 
            WHERE id = %s AND officer_gmail = %s
        """, (policy_id, current_user.id))
        
        deleted_count = cursor.rowcount
        conn.commit()

        return jsonify({
            'success': True, 
            'message': f'成功刪除保單: {policy["policy_number"]}',
            'deleted_policy': {
                'id': policy_id,
                'policy_number': policy['policy_number'],
                'client_gmail': policy['client_gmail']
            }
        })
                
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"刪除保單草稿錯誤: {str(e)}")
        return jsonify({'success': False, 'message': f'刪除過程中發生錯誤: {str(e)}'})
    finally:
        if conn:
            conn.close()