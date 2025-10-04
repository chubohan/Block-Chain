from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session
from utils.db import get_connection
from flask_login import current_user,login_required
policy_bp = Blueprint('policy', __name__)

# 我的保單主頁
@policy_bp.route('/mypolicy')
@login_required
def my_policies():
    user_email = current_user.id
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # 假設 status = 0 是待確認，status = 1 是已完成
            cursor.execute("SELECT * FROM policy_draft WHERE client_gmail = %s AND (status IS NULL OR status = 0)", (user_email,))
            pending_policies = cursor.fetchall()

            cursor.execute("SELECT * FROM policy_draft WHERE client_gmail = %s AND status = 1", (user_email,))
            completed_policies = cursor.fetchall()
    finally:
        conn.close()

    return render_template('policy/mypolicy.html',
                           pending_policies=pending_policies,
                           completed_policies=completed_policies)

# 刪除保單路由 - 改為返回 JSON 回應
# 刪除保單路由 - 修正參數名稱
@policy_bp.route('/delete_policy/<policy_number>', methods=['POST'])
@login_required
def delete_policy(policy_number):  # 參數名稱改為 policy_number
    user_email = current_user.id
    
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        print(f"開始刪除保單: {policy_number}, 用戶: {user_email}")

        # 檢查保單是否存在且屬於當前用戶
        cursor.execute("""
            SELECT policy_id, client_gmail 
            FROM policy 
            WHERE policy_id = %s AND client_gmail = %s
        """, (policy_number, user_email))
        
        policy = cursor.fetchone()
        
        if not policy:
            return jsonify({'success': False, 'message': '保單不存在或您沒有權限刪除'})

        # 在同一個 transaction 中刪除兩個資料表的記錄
        # 先刪除 policy_draft
        cursor.execute("""
            DELETE FROM policy_draft 
            WHERE client_gmail = %s AND policy_number = %s
        """, (user_email, policy_number))
        draft_deleted = cursor.rowcount

        # 再刪除 policy
        cursor.execute("""
            DELETE FROM policy 
            WHERE client_gmail = %s AND policy_id = %s
        """, (user_email, policy_number))
        policy_deleted = cursor.rowcount

        conn.commit()
        
        print(f"刪除結果 - 草稿表: {draft_deleted} 條, 政策表: {policy_deleted} 條")
        
        return jsonify({
            'success': True, 
            'message': f'保單刪除成功！',
            'details': {
                'draft_deleted': draft_deleted,
                'policy_deleted': policy_deleted
            }
        })
                
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"刪除保單錯誤: {str(e)}")
        return jsonify({'success': False, 'message': f'刪除過程中發生錯誤: {str(e)}'})
    finally:
        if conn:
            conn.close()
@policy_bp.route('/get_wallet', methods=['GET'])
@login_required
def get_wallet():
    user_email = current_user.id
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT wallet FROM user WHERE gmail = %s", (user_email,))
            wallet = cursor.fetchone()
            if not wallet or not wallet['wallet']:
                return jsonify({'success': False, 'message': '未綁定錢包'})
            return jsonify({'success': True, 'wallet': wallet['wallet']})
    finally:
        conn.close()

# 詳細資料
@policy_bp.route('/confirm/<policy_number>')
@login_required
def confirm_policy(policy_number):
    user_email = current_user.id
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM policy_draft WHERE policy_number = %s AND client_gmail = %s", (policy_number, user_email))
            policy = cursor.fetchone()
            if not policy:
                return "找不到保單", 404
    finally:
        conn.close()
    return render_template('policy/create_form.html', policy=policy)

@policy_bp.route('/get_wallet_addresses')
@login_required
def get_wallet_addresses():
    """獲取用戶和業務員的錢包地址"""
    user_email = current_user.id
    
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # 獲取當前用戶的錢包地址
            cursor.execute("SELECT wallet FROM user WHERE gmail = %s", (user_email,))
            user_wallet = cursor.fetchone()
            
            # 獲取業務員的錢包地址（從保單草稿中獲取業務員郵件）
            cursor.execute(
                "SELECT officer_gmail FROM policy_draft WHERE client_gmail = %s LIMIT 1", 
                (user_email,)
            )
            policy_draft = cursor.fetchone()
            
            officer_wallet = None
            if policy_draft and policy_draft['officer_gmail']:
                cursor.execute(
                    "SELECT wallet FROM user WHERE gmail = %s", 
                    (policy_draft['officer_gmail'],)
                )
                officer_wallet = cursor.fetchone()
            
            return jsonify({
                'success': True,
                'user_wallet': user_wallet['wallet'] if user_wallet and user_wallet['wallet'] else None,
                'officer_wallet': officer_wallet['wallet'] if officer_wallet and officer_wallet['wallet'] else None
            })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        conn.close()

@policy_bp.route('/get_user_wallet')
@login_required
def get_user_wallet():
    """獲取當前用戶的錢包地址"""
    user_email = current_user.id
    
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT wallet FROM user WHERE gmail = %s", (user_email,))
            result = cursor.fetchone()
            
            if result and result['wallet']:
                return jsonify({
                    'success': True, 
                    'wallet_address': result['wallet']
                })
            else:
                return jsonify({
                    'success': False, 
                    'error': '用戶錢包地址未設定'
                })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        conn.close()

@policy_bp.route('/get_officer_wallet/<officer_gmail>')
@login_required
def get_officer_wallet(officer_gmail):
    """獲取業務員的錢包地址"""
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT wallet FROM user WHERE gmail = %s", (officer_gmail,))
            result = cursor.fetchone()
            
            if result and result['wallet']:
                return jsonify({
                    'success': True, 
                    'wallet_address': result['wallet']
                })
            else:
                return jsonify({
                    'success': False, 
                    'error': '業務員錢包地址未設定'
                })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        conn.close()

@policy_bp.route('/create_and_confirm', methods=['POST'])
@login_required
def create_and_confirm():
    data = request.json
    print("✅ 收到前端資料：", data)

    # 必要欄位檢查
    required_fields = ['policy_number', 'policy_holder', 'insured_person', 'insurance_amount']
    for field in required_fields:
        if not data.get(field):
            return jsonify(success=False, message=f"{field} 欄位缺失")

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # 1️⃣ 儲存到 policy_draft
            # policy_draft 插入語句（保持不變，包含 pdf_filename）
            insert_draft_sql = """
                INSERT INTO policy_draft (
                    policy_number, insurance_company, policy_holder, insured_person,
                    insurance_amount, premium_period, premium_amount, start_date,
                    beneficiary, growth_rate, declared_interest_rate,
                    pdf_hash, pdf_filename, client_gmail, officer_gmail, created_at, status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), 1)
                ON DUPLICATE KEY UPDATE
                    policy_holder = VALUES(policy_holder),
                    insured_person = VALUES(insured_person),
                    insurance_amount = VALUES(insurance_amount),
                    premium_period = VALUES(premium_period),
                    premium_amount = VALUES(premium_amount),
                    start_date = VALUES(start_date),
                    beneficiary = VALUES(beneficiary),
                    growth_rate = VALUES(growth_rate),
                    declared_interest_rate = VALUES(declared_interest_rate),
                    pdf_hash = VALUES(pdf_hash),
                    pdf_filename = VALUES(pdf_filename),
                    officer_gmail = VALUES(officer_gmail),
                    client_gmail = VALUES(client_gmail),
                    status = 1
            """
            cursor.execute(insert_draft_sql, (
                data.get('policy_number'),
                data.get('insurance_company'),
                data.get('policy_holder'),
                data.get('insured_person'),
                data.get('insurance_amount'),
                data.get('premium_period'),
                data.get('premium_amount'),
                data.get('start_date'),
                data.get('beneficiary'),
                data.get('growth_rate'),
                data.get('declared_interest_rate'),
                data.get('pdf_hash'),
                data.get('pdf_filename'),  # 這裡有
                data.get('client_gmail'),
                data.get('officer_gmail')
            ))

            # policy 表插入語句，**不要帶入 pdf_filename**
            insert_policy_sql = """
                INSERT INTO policy (
                    policy_id, policyHolder, insuredPerson, insuranceAmount,
                    premiumPeriod, premiumAmount, startDate, beneficiary,
                    growthRate, declaredInterestRate, company,
                    client_gmail, officer_gmail, pdf_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    policyHolder = VALUES(policyHolder),
                    insuredPerson = VALUES(insuredPerson),
                    insuranceAmount = VALUES(insuranceAmount),
                    premiumPeriod = VALUES(premiumPeriod),
                    premiumAmount = VALUES(premiumAmount),
                    startDate = VALUES(startDate),
                    beneficiary = VALUES(beneficiary),
                    growthRate = VALUES(growthRate),
                    declaredInterestRate = VALUES(declaredInterestRate),
                    company = VALUES(company),
                    client_gmail = VALUES(client_gmail),
                    officer_gmail = VALUES(officer_gmail),
                    pdf_hash = VALUES(pdf_hash)
            """
            cursor.execute(insert_policy_sql, (
                data.get('policy_number'),
                data.get('policy_holder'),
                data.get('insured_person'),
                data.get('insurance_amount'),
                data.get('premium_period'),
                data.get('premium_amount'),
                data.get('start_date'),
                data.get('beneficiary'),
                data.get('growth_rate'),
                data.get('declared_interest_rate'),
                data.get('insurance_company'),
                data.get('client_gmail'),
                data.get('officer_gmail'),
                data.get('pdf_hash')
            ))

            # 3️⃣ 刪除原本 policy_draft 草稿（不管 status）
            delete_draft_sql = """
                DELETE FROM policy_draft WHERE policy_number = %s and status=0
            """
            cursor.execute(delete_draft_sql, (data.get('policy_number'),))

            conn.commit()
        return jsonify(success=True, message="保單已儲存並確認")
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"儲存失敗：{str(e)}")
    finally:
        conn.close()

# 編輯保單頁
@policy_bp.route('/policy/edit/<policy_id>', methods=['GET', 'POST'])
def edit_policy(policy_id):
    user_email = session.get('user_email')
    if not user_email:
        return redirect(url_for('user.login'))

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            if request.method == 'POST':
                data = request.form

                update_sql = """
                    UPDATE policy_draft SET
                        policy_number = %s,
                        insurance_company = %s,
                        policy_holder = %s,
                        insured_person = %s,
                        insurance_amount = %s,
                        premium_period = %s,
                        premium_amount = %s,
                        start_date = %s,
                        beneficiary = %s,
                        growth_rate = %s,
                        declared_interest_rate = %s
                    WHERE id = %s AND client_gmail = %s
                """
                cursor.execute(update_sql, (
                    data.get('policy_number'),
                    data.get('insurance_company'),
                    data.get('policy_holder'),
                    data.get('insured_person'),
                    data.get('insurance_amount'),
                    data.get('premium_period'),
                    data.get('premium_amount'),
                    data.get('start_date'),
                    data.get('beneficiary'),
                    data.get('growth_rate'),
                    data.get('declared_interest_rate'),
                    policy_id,
                    user_email
                ))
                
                conn.commit()
                return redirect(url_for('policy.confirm_policy', policy_id=policy_id))

            # GET 載入草稿
            cursor.execute("SELECT * FROM policy_draft WHERE id = %s AND client_gmail = %s", (policy_id, user_email))
            policy = cursor.fetchone()

            if not policy:
                return "找不到保單或無權限", 403

    finally:
        conn.close()

    return render_template('edit_policy.html', policy=policy)@policy_bp.route('/completed_policy_form', methods=['GET'])
@policy_bp.route('/completed_policy_form', methods=['GET'])
@login_required
def completed_policy_form():
    policy_number = request.args.get('policy_number')

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM policy WHERE policy_id = %s", (policy_number,))
            policy = cursor.fetchone()

            if not policy:
                
                return redirect(url_for('policy.read_policy_form'))

            return render_template('policy/completed_policy_form.html', policy=policy)
    finally:
        conn.close()

@policy_bp.route('/authorization/<policy_number>', methods=['GET'])
@login_required
def authorization_page(policy_number):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT gmail, authorized_gmail, relationship
            FROM authorization
            WHERE policy_number = %s
        ''', (policy_number,))
        rows = cursor.fetchall()

        

        cursor.close()
        conn.close()

        return render_template('/policy/authorization_page.html',
                               policy_number=policy_number,
                               authorized_list=rows)

    except Exception as e:
        print(e)
        return render_template('/policy/authorization_page.html',
                               policy_number=policy_number,
                               authorized_list=[],
                               error='查詢失敗')
'''
# 顯示授權管理頁面
@policy_bp.route('/authorization')
@login_required
def authorization():
    user_email = current_user.id
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM authorization WHERE gmail = %s", (user_email,))
            auths = cursor.fetchall()
        return render_template('/policy/authorization.html', auths=auths, current_user_email=user_email)
    finally:
        conn.close()
'''
# 新增授權 API (改進版)
@policy_bp.route('/add-authorization', methods=['POST'])
@login_required
def add_authorization():
    try:
        data = request.get_json()
        gmail = current_user.id
        authorized_gmail = data.get('authorized_gmail')
        authorized_wallet = data.get('authorized_wallet')
        relationship = data.get('relationship')
        policy_number = data.get('policy_number')
        tx_hash = data.get('tx_hash')

        if not all([gmail, relationship, policy_number]):
            return jsonify({'success': False, 'message': '缺少必要欄位'}), 400

        # 檢查至少提供 gmail 或 wallet 其中一項
        if not authorized_gmail and not authorized_wallet:
            return jsonify({'success': False, 'message': '請提供被授權人 Gmail 或錢包地址'}), 400

        conn = get_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # 如果提供了 gmail，驗證該用戶是否存在
        if authorized_gmail:
            cursor.execute("SELECT gmail, wallet FROM user WHERE gmail = %s", (authorized_gmail,))
            user_exists = cursor.fetchone()
            
            if not user_exists:
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'message': '被授權人尚未註冊系統'}), 400
            
            # 如果同時提供了 wallet，檢查是否與用戶的 wallet 匹配
            if authorized_wallet and user_exists['wallet']:
                if authorized_wallet.lower() != user_exists['wallet'].lower():
                    cursor.close()
                    conn.close()
                    return jsonify({
                        'success': False, 
                        'message': '提供的錢包地址與該用戶註冊的錢包不匹配'
                    }), 400
            # 如果沒提供 wallet，使用用戶註冊的 wallet
            elif not authorized_wallet and user_exists['wallet']:
                authorized_wallet = user_exists['wallet']
            elif not authorized_wallet and not user_exists['wallet']:
                cursor.close()
                conn.close()
                return jsonify({
                    'success': False, 
                    'message': '該用戶未註冊錢包地址，請直接輸入錢包地址'
                }), 400

        # 如果只提供了 wallet，檢查該 wallet 是否已註冊
        elif authorized_wallet and not authorized_gmail:
            cursor.execute("SELECT gmail FROM user WHERE wallet = %s", (authorized_wallet,))
            wallet_user = cursor.fetchone()
            if wallet_user:
                authorized_gmail = wallet_user['gmail']

        # 檢查是否已經存在相同的授權記錄
        if authorized_gmail:
            cursor.execute(
                '''SELECT id FROM authorization 
                WHERE policy_number = %s AND (authorized_gmail = %s OR authorized_wallet = %s)''',
                (policy_number, authorized_gmail, authorized_wallet)
            )
        else:
            cursor.execute(
                '''SELECT id FROM authorization 
                WHERE policy_number = %s AND authorized_wallet = %s''',
                (policy_number, authorized_wallet)
            )
        
        existing_auth = cursor.fetchone()
        if existing_auth:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': '該用戶已被授權'}), 400

        # 插入授權記錄
        cursor.execute('''
            INSERT INTO authorization (policy_number, gmail, authorized_gmail, authorized_wallet, relationship, tx_hash)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (policy_number, gmail, authorized_gmail, authorized_wallet, relationship, tx_hash))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': '授權成功'})

    except Exception as e:
        print("add_authorization error:", e)
        if 'conn' in locals():
            conn.rollback()
            cursor.close()
            conn.close()
        return jsonify({'success': False, 'message': '授權失敗: ' + str(e)})
# 刪除授權 API (改進版)
@policy_bp.route('/delete-authorization', methods=['POST'])
@login_required
def delete_authorization():
    try:
        data = request.get_json()
        policy_number = data.get('policy_number')
        authorized_gmail = data.get('authorized_gmail')
        authorized_wallet = data.get('authorized_wallet')

        if not policy_number:
            return jsonify({'success': False, 'message': '缺少保單編號'}), 400

        if not authorized_gmail and not authorized_wallet:
            return jsonify({'success': False, 'message': '請提供被授權人 Gmail 或錢包地址'}), 400

        conn = get_connection()
        cursor = conn.cursor()

        # 根據提供的條件刪除授權
        if authorized_gmail and authorized_wallet:
            cursor.execute(
                '''DELETE FROM authorization 
                WHERE policy_number = %s AND authorized_gmail = %s AND authorized_wallet = %s''',
                (policy_number, authorized_gmail, authorized_wallet)
            )
        elif authorized_gmail:
            cursor.execute(
                '''DELETE FROM authorization 
                WHERE policy_number = %s AND authorized_gmail = %s''',
                (policy_number, authorized_gmail)
            )
        else:
            cursor.execute(
                '''DELETE FROM authorization 
                WHERE policy_number = %s AND authorized_wallet = %s''',
                (policy_number, authorized_wallet)
            )

        affected_rows = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()

        if affected_rows > 0:
            return jsonify({'success': True, 'message': '刪除成功'})
        else:
            return jsonify({'success': False, 'message': '找不到對應的授權記錄'})

    except Exception as e:
        print("delete_authorization error:", e)
        if 'conn' in locals():
            conn.rollback()
            cursor.close()
            conn.close()
        return jsonify({'success': False, 'message': '刪除失敗: ' + str(e)}), 500
import pymysql.cursors  # 確保有這行
# 查詢使用者錢包地址
@policy_bp.route('/get-wallet-address', methods=['POST'])
@login_required
def get_wallet_address():
    data = request.get_json()
    gmail = data.get('gmail')

    if not gmail:
        return jsonify({'success': False, 'message': '缺少 Gmail'}), 400

    try:
        conn = get_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT wallet FROM user WHERE gmail = %s", (gmail,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if row and row['wallet']:
            return jsonify({'success': True, 'wallet': row['wallet']})
        else:
            return jsonify({'success': False, 'message': '查無此用戶或未註冊錢包'})
    except Exception as e:
        print("get_wallet_address error:", e)
        return jsonify({'success': False, 'message': '伺服器錯誤'})
    
@policy_bp.route('/get-authorizations/<policy_number>', methods=['GET'])
@login_required
def get_authorizations(policy_number):
    try:
        conn = get_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        cursor.execute('''
            SELECT a.gmail, a.authorized_gmail, a.authorized_wallet, a.relationship, a.tx_hash,
                   u1.username as policy_holder_name,
                   u2.username as authorized_user_name
            FROM authorization a
            LEFT JOIN user u1 ON a.gmail = u1.gmail
            LEFT JOIN user u2 ON a.authorized_gmail = u2.gmail
            WHERE a.policy_number = %s
        ''', (policy_number,))
        
        rows = cursor.fetchall()
        print("查詢保單編號：", policy_number)
        print("查詢結果：", rows)
        
        authorized_list = []
        for row in rows:
            # 確定顯示名稱：優先使用授權用戶名，然後是 Gmail，最後是錢包
            if row['authorized_user_name']:
                display_name = f"{row['authorized_user_name']} ({row['authorized_gmail']})"
            elif row['authorized_gmail']:
                display_name = row['authorized_gmail']
            else:
                display_name = row['authorized_wallet']
            
            authorized_list.append({
                'gmail': row['gmail'],
                'authorized_gmail': row['authorized_gmail'],
                'authorized_wallet': row['authorized_wallet'],
                'relationship': row['relationship'],
                'display_name': display_name,
                'policy_holder_name': row['policy_holder_name'],
                'authorized_user_name': row['authorized_user_name'],
                'tx_hash': row['tx_hash']
            })
        
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'authorized_list': authorized_list})

    except Exception as e:
        print("get_authorizations error:", e)
        return jsonify({'success': False, 'message': '查詢失敗: ' + str(e)})
# 檢查用戶是否存在
@policy_bp.route('/check-user-exists', methods=['POST'])
@login_required
def check_user_exists():
    data = request.get_json()
    gmail = data.get('gmail')

    if not gmail:
        return jsonify({'success': False, 'message': '缺少 Gmail'}), 400

    try:
        conn = get_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        
        # 查詢用戶是否存在及錢包信息
        cursor.execute("SELECT gmail, wallet, username FROM user WHERE gmail = %s", (gmail,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if row:
            return jsonify({
                'success': True, 
                'exists': True,
                'gmail': row['gmail'],
                'wallet': row['wallet'],
                'username': row['username'],
                'message': '用戶存在'
            })
        else:
            return jsonify({
                'success': True, 
                'exists': False, 
                'message': '用戶未註冊'
            })
            
    except Exception as e:
        print("check_user_exists error:", e)
        return jsonify({'success': False, 'message': '伺服器錯誤'})
    
# 查詢錢包對應的用戶
@policy_bp.route('/get-user-by-wallet', methods=['POST'])
@login_required
def get_user_by_wallet():
    data = request.get_json()
    wallet = data.get('wallet')

    if not wallet:
        return jsonify({'success': False, 'message': '缺少錢包地址'}), 400

    try:
        conn = get_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT gmail, username, wallet FROM user WHERE wallet = %s", (wallet,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if row:
            return jsonify({
                'success': True, 
                'user': {
                    'gmail': row['gmail'],
                    'username': row['username'],
                    'wallet': row['wallet']
                }
            })
        else:
            return jsonify({'success': False, 'message': '查無此錢包對應的用戶'})
    except Exception as e:
        print("get_user_by_wallet error:", e)
        return jsonify({'success': False, 'message': '伺服器錯誤'})    
    
# 查詢被授權的保單（修正版）
@policy_bp.route('/authorized_policies')
@login_required
def authorized_policies():
    user_email = current_user.id
    
    conn = get_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            print(f"正在查詢用戶 {user_email} 的被授權保單...")
            
            # 獲取當前用戶的錢包地址
            cursor.execute("SELECT wallet, username FROM user WHERE gmail = %s", (user_email,))
            user_result = cursor.fetchone()
            
            if not user_result:
                print(f"用戶 {user_email} 不存在")
                return render_template('policy/authorized_policies.html', 
                                     authorized_policies=[], 
                                     error="用戶不存在")
            
            user_wallet = user_result['wallet']
            user_name = user_result['username']
            
            print(f"用戶錢包: {user_wallet}, 用戶姓名: {user_name}")
            
            # 先檢查 authorization 表的結構
            cursor.execute("DESCRIBE authorization")
            auth_columns = [col['Field'] for col in cursor.fetchall()]
            print(f"authorization 表欄位: {auth_columns}")
            
            # 根據實際欄位動態建立查詢
            select_fields = [
                'a.policy_number',
                'a.gmail as grantor_gmail',
                'a.authorized_gmail',
                'a.authorized_wallet',
                'a.relationship',
                'a.tx_hash',
                'p.policyHolder',
                'p.insuredPerson',
                'p.insuranceAmount',
                'p.premiumPeriod',
                'p.premiumAmount',
                'p.startDate',
                'p.beneficiary',
                'p.growthRate',
                'p.declaredInterestRate',
                'p.company',
                'u_grantor.username as grantor_name',
                'u_grantor.wallet as grantor_wallet'
            ]
            
            # 如果有 created_at 欄位就加入
            if 'created_at' in auth_columns:
                select_fields.append('a.created_at as authorized_date')
            else:
                # 如果沒有 created_at，使用其他欄位或當前時間
                select_fields.append('NOW() as authorized_date')
            
            query = f'''
                SELECT 
                    {', '.join(select_fields)}
                FROM authorization a
                LEFT JOIN policy p ON a.policy_number = p.policy_id
                LEFT JOIN user u_grantor ON a.gmail = u_grantor.gmail
                WHERE a.authorized_gmail = %s OR a.authorized_wallet = %s
            '''
            
            # 如果有 created_at 就排序
            if 'created_at' in auth_columns:
                query += ' ORDER BY a.created_at DESC'
            
            print(f"執行查詢: {query}")
            print(f"查詢參數: authorized_gmail={user_email}, authorized_wallet={user_wallet}")
            
            cursor.execute(query, (user_email, user_wallet))
            authorized_policies = cursor.fetchall()
            
            print(f"查詢結果數量: {len(authorized_policies)}")
            
            # 處理查詢結果，確保資料格式一致
            processed_policies = []
            for policy in authorized_policies:
                print(f"處理保單: {policy}")
                processed_policy = {
                    'policy_number': policy['policy_number'],
                    'grantor_gmail': policy['grantor_gmail'],
                    'grantor_name': policy['grantor_name'],
                    'grantor_wallet': policy['grantor_wallet'],
                    'relationship': policy['relationship'],
                    'authorized_date': policy.get('authorized_date'),
                    'tx_hash': policy['tx_hash'],
                    'policyHolder': policy['policyHolder'],
                    'insuredPerson': policy['insuredPerson'],
                    'insuranceAmount': policy['insuranceAmount'],
                    'premiumPeriod': policy['premiumPeriod'],
                    'premiumAmount': policy['premiumAmount'],
                    'startDate': policy['startDate'],
                    'beneficiary': policy['beneficiary'],
                    'growthRate': policy['growthRate'],
                    'declaredInterestRate': policy['declaredInterestRate'],
                    'company': policy['company']
                }
                processed_policies.append(processed_policy)
            
            return render_template('policy/authorized_policies.html', 
                                 authorized_policies=processed_policies,
                                 user_email=user_email,
                                 user_wallet=user_wallet,
                                 user_name=user_name)
            
    except Exception as e:
        print(f"查詢被授權保單錯誤: {e}")
        import traceback
        traceback.print_exc()
        return render_template('policy/authorized_policies.html', 
                             authorized_policies=[], 
                             error=f"查詢失敗: {str(e)}")
    finally:
        conn.close()

# 新增：除錯用 API，檢查授權狀態
@policy_bp.route('/debug_authorizations')
@login_required
def debug_authorizations():
    """除錯用 API，檢查當前用戶的授權狀態"""
    user_email = current_user.id
    
    conn = get_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            # 獲取用戶錢包
            cursor.execute("SELECT wallet FROM user WHERE gmail = %s", (user_email,))
            user_result = cursor.fetchone()
            user_wallet = user_result['wallet'] if user_result else None
            
            # 查詢所有授權記錄
            cursor.execute('''
                SELECT * FROM authorization 
                WHERE authorized_gmail = %s OR authorized_wallet = %s
            ''', (user_email, user_wallet))
            auth_records = cursor.fetchall()
            
            # 查詢所有保單
            cursor.execute("SELECT policy_id FROM policy")
            all_policies = cursor.fetchall()
            
            return jsonify({
                'user_email': user_email,
                'user_wallet': user_wallet,
                'authorization_records': auth_records,
                'all_policies': all_policies,
                'auth_count': len(auth_records)
            })
            
    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        conn.close()

# API: 獲取被授權保單詳細資料（修正版）
@policy_bp.route('/get_authorized_policy_detail/<policy_number>')
@login_required
def get_authorized_policy_detail(policy_number):
    user_email = current_user.id
    
    conn = get_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            # 先獲取用戶錢包地址
            cursor.execute("SELECT wallet FROM user WHERE gmail = %s", (user_email,))
            user_wallet_result = cursor.fetchone()
            user_wallet = user_wallet_result['wallet'] if user_wallet_result else None
            
            # 檢查 authorization 表結構
            cursor.execute("DESCRIBE authorization")
            auth_columns = [col['Field'] for col in cursor.fetchall()]
            
            # 動態建立查詢欄位
            select_fields = [
                'a.*',
                'p.*',
                'u_grantor.username as grantor_name',
                'u_grantor.wallet as grantor_wallet',
                'u_authorized.username as authorized_name'
            ]
            
            query = f'''
                SELECT 
                    {', '.join(select_fields)}
                FROM authorization a
                JOIN policy p ON a.policy_number = p.policy_id
                LEFT JOIN user u_grantor ON a.gmail = u_grantor.gmail
                LEFT JOIN user u_authorized ON a.authorized_gmail = u_authorized.gmail
                WHERE a.policy_number = %s AND (a.authorized_gmail = %s OR a.authorized_wallet = %s)
            '''
            
            cursor.execute(query, (policy_number, user_email, user_wallet))
            policy_auth = cursor.fetchone()
            
            if not policy_auth:
                return jsonify(success=False, message="無權限查看此保單")
            
            # 處理授權日期
            authorized_date = None
            if 'created_at' in auth_columns and policy_auth['created_at']:
                authorized_date = policy_auth['created_at'].strftime('%Y-%m-%d %H:%M')
            
            # 返回保單詳細資料
            policy_data = {
                'policy_number': policy_auth['policy_id'],
                'policy_holder': policy_auth['policyHolder'],
                'insured_person': policy_auth['insuredPerson'],
                'insurance_amount': policy_auth['insuranceAmount'],
                'premium_period': policy_auth['premiumPeriod'],
                'premium_amount': policy_auth['premiumAmount'],
                'start_date': policy_auth['startDate'].strftime('%Y-%m-%d') if policy_auth['startDate'] else None,
                'beneficiary': policy_auth['beneficiary'],
                'growth_rate': policy_auth['growthRate'],
                'declared_interest_rate': policy_auth['declaredInterestRate'],
                'company': policy_auth['company'],
                
                # 授權人資訊
                'grantor_gmail': policy_auth['gmail'],
                'grantor_name': policy_auth['grantor_name'],
                'grantor_wallet': policy_auth['grantor_wallet'],
                
                # 被授權人資訊
                'authorized_gmail': policy_auth['authorized_gmail'],
                'authorized_wallet': policy_auth['authorized_wallet'],
                'authorized_name': policy_auth['authorized_name'],
                
                # 授權關係資訊
                'relationship': policy_auth['relationship'],
                'authorized_date': authorized_date,
                'tx_hash': policy_auth['tx_hash']
            }
            
            return jsonify(success=True, policy=policy_data)
            
    except Exception as e:
        print(f"獲取被授權保單詳細資料錯誤: {e}")
        return jsonify(success=False, message="查詢失敗")
    finally:
        conn.close()

# 新增：檢查區塊鏈授權狀態
@policy_bp.route('/check_blockchain_authorization/<policy_number>')
@login_required
def check_blockchain_authorization(policy_number):
    user_email = current_user.id
    
    conn = get_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            # 獲取用戶錢包
            cursor.execute("SELECT wallet FROM user WHERE gmail = %s", (user_email,))
            user_wallet_result = cursor.fetchone()
            
            if not user_wallet_result or not user_wallet_result['wallet']:
                return jsonify(success=False, message="未找到用戶錢包")
            
            user_wallet = user_wallet_result['wallet']
            
            # 檢查資料庫授權記錄
            cursor.execute('''
                SELECT * FROM authorization 
                WHERE policy_number = %s AND (authorized_gmail = %s OR authorized_wallet = %s)
            ''', (policy_number, user_email, user_wallet))
            
            auth_record = cursor.fetchone()
            
            if not auth_record:
                return jsonify(success=False, message="無授權記錄")
            
            return jsonify(success=True, 
                         has_database_auth=True,
                         authorized_gmail=auth_record['authorized_gmail'],
                         authorized_wallet=auth_record['authorized_wallet'],
                         relationship=auth_record['relationship'])
            
    except Exception as e:
        print(f"檢查區塊鏈授權錯誤: {e}")
        return jsonify(success=False, message="檢查失敗")
    finally:
        conn.close()

