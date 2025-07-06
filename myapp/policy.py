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

    # 必要欄位檢查
    required_fields = ['policy_number', 'policy_holder', 'insured_person', 'insurance_amount']
    for field in required_fields:
        if not data.get(field):
            return jsonify(success=False, message=f"{field} 欄位缺失")

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # 1️⃣ 儲存到 policy_draft
            insert_draft_sql = """
                INSERT INTO policy_draft (
                    client_gmail, policy_number, insurance_company, policy_holder, insured_person,
                    insurance_amount, premium_period, premium_amount, start_date, beneficiary,
                    growth_rate, declared_interest_rate, pdf_filename, officer_gmail, created_at, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), 1)
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
                    pdf_filename = VALUES(pdf_filename),
                    officer_gmail = VALUES(officer_gmail),
                    status = 1
            """
            cursor.execute(insert_draft_sql, (
                data.get('client_gmail', ''),
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
                data.get('pdf_filename', ''),
                data.get('officer_gmail', '')
            ))

            # 2️⃣ 同步寫入 policy 正式表
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
                data.get('client_gmail', ''),
                data.get('officer_gmail', ''),
                data.get('pdf_filename', '')
            ))
            # 刪除對應的 policy_draft
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