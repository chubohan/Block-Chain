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
# 新增授權 API
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

        if not all([gmail, authorized_wallet, relationship, policy_number]):
            return jsonify({'success': False, 'message': '缺少必要欄位'}), 400

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO authorization (policy_number, gmail, authorized_gmail, authorized_wallet, relationship, tx_hash)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
                relationship = VALUES(relationship),
                tx_hash = VALUES(tx_hash),
                authorized_wallet = VALUES(authorized_wallet)
        ''', (policy_number, gmail, authorized_gmail, authorized_wallet, relationship, tx_hash))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': '授權成功'})

    except Exception as e:
        print(e)
        return jsonify({'success': False, 'message': '授權失敗'})
    
# 刪除授權 API
@policy_bp.route('/delete-authorization', methods=['POST'])
@login_required
def delete_authorization():
    data = request.get_json()
    policy_number = data.get('policy_number')
    authorized_gmail = data.get('authorized_gmail')

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            'DELETE FROM authorization WHERE policy_number = %s AND authorized_gmail = %s',
            (policy_number, authorized_gmail)
        )
        conn.commit()
        return jsonify({'success': True, 'message': '刪除成功'})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

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
        cursor = conn.cursor()

        cursor.execute('''
            SELECT gmail, authorized_gmail, relationship
            FROM authorization
            WHERE policy_number = %s
        ''', (policy_number,))
        rows = cursor.fetchall()
        print("查詢保單編號：", policy_number)
        print("查詢結果：", rows)
        # 將 tuple list 轉成 list of dicts
        authorized_list = [
            {'gmail': row[0], 'authorized_gmail': row[1], 'relationship': row[2]}
            for row in rows
        ]
        
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'authorized_list': authorized_list})

    except Exception as e:
        print(e)
        return jsonify({'success': False, 'message': '查詢失敗'})
