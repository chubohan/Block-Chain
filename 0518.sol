// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract InsurancePolicy {
    struct Policy {
        string policyNumber;       // 保單號碼（字串）
        string policyHolder;       // 投保人姓名
        string insuredPerson;      // 被保險人姓名
        uint insuranceAmount;      // 保險金額
        uint premiumPeriod;        // 繳費期間（年）
        uint premiumAmount;        // 每期保費金額
        uint startDate;            // 生效日期（Unix Timestamp）
        string beneficiary;        // 受益人資訊
        uint growthRate;           // 增額比例（百分比）
        uint declaredInterestRate; // 宣告利率（百分比）
        address owner;             // 記錄該保單的擁有者
        string pdfHash;            // 保單 PDF 的去中心化存儲 Hash
    }

    mapping(string => Policy) public policies; // 透過保單號碼（字串）來儲存保單
    string[] public policyNumbers; // 儲存所有的保單號碼

    modifier onlyOwner(string memory _policyNumber) {
        require(policies[_policyNumber].owner == msg.sender, "Not the policy owner");
        _;
    }

    // 新增保單
    function addPolicy(
        string memory _policyNumber,
        string memory _policyHolder,
        string memory _insuredPerson,
        uint _insuranceAmount,
        uint _premiumPeriod,
        uint _premiumAmount,
        uint _startDate,
        string memory _beneficiary,
        uint _growthRate,
        uint _declaredInterestRate,
        string memory _pdfHash
    ) public {
        require(bytes(policies[_policyNumber].policyNumber).length == 0, "Policy number already exists");
        policies[_policyNumber] = Policy(
            _policyNumber, 
            _policyHolder, 
            _insuredPerson, 
            _insuranceAmount, 
            _premiumPeriod, 
            _premiumAmount, 
            _startDate, 
            _beneficiary, 
            _growthRate, 
            _declaredInterestRate, 
            msg.sender,
            _pdfHash
        );
        policyNumbers.push(_policyNumber);
    }

    // 查詢保單
    function getPolicy(string memory _policyNumber) public view onlyOwnerOrAuthorized(_policyNumber) returns (
        string memory,
        string memory,
        uint,
        uint,
        uint,
        uint,
        string memory,
        uint,
        uint,
        string memory
    ) {
        Policy memory policy = policies[_policyNumber];
        require(bytes(policy.policyNumber).length != 0, "Policy not found");
        return (
            policy.policyHolder,
            policy.insuredPerson,
            policy.insuranceAmount,
            policy.premiumPeriod,
            policy.premiumAmount,
            policy.startDate,
            policy.beneficiary,
            policy.growthRate,
            policy.declaredInterestRate,
            policy.pdfHash
        );
    }

    // 更新保單
    function updatePolicy(
        string memory _policyNumber,
        uint _insuranceAmount,
        uint _premiumAmount,
        uint _growthRate,
        uint _declaredInterestRate
    ) public onlyOwner(_policyNumber) {
        require(bytes(policies[_policyNumber].policyNumber).length != 0, "Policy not found");
        policies[_policyNumber].insuranceAmount = _insuranceAmount;
        policies[_policyNumber].premiumAmount = _premiumAmount;
        policies[_policyNumber].growthRate = _growthRate;
        policies[_policyNumber].declaredInterestRate = _declaredInterestRate;
    }

    // 更新 PDF 檔案
    function updatePolicyPDF(string memory _policyNumber, string memory _pdfHash) public onlyOwner(_policyNumber) {
        require(bytes(policies[_policyNumber].policyNumber).length != 0, "Policy not found");
        policies[_policyNumber].pdfHash = _pdfHash;
    }

    // 刪除保單（只能由保單擁有者操作）
    function deletePolicy(string memory _policyNumber) public onlyOwner(_policyNumber) {
        require(bytes(policies[_policyNumber].policyNumber).length != 0, "Policy not found");
        delete policies[_policyNumber];
        // 移除 policyNumbers 陣列中的對應保單號碼
        for (uint i = 0; i < policyNumbers.length; i++) {
            if (keccak256(abi.encodePacked(policyNumbers[i])) == keccak256(abi.encodePacked(_policyNumber))) {
                policyNumbers[i] = policyNumbers[policyNumbers.length - 1];
                policyNumbers.pop();
                break;
            }
        }
    }



    // 新增授权映射：保單號碼 => 授權地址 => 是否授權
    mapping(string => mapping(address => bool)) private _policyAuthorized;

    // 修改修饰符：允许所有者或授权地址
    modifier onlyOwnerOrAuthorized(string memory _policyNumber) {
        require(
            policies[_policyNumber].owner == msg.sender ||
            _policyAuthorized[_policyNumber][msg.sender],
            "No permission"
        );
        _;
    }

    // 新增授权函数
    function authorizePolicyAccess(string memory _policyNumber, address _wallet) external onlyOwner(_policyNumber) {
        _policyAuthorized[_policyNumber][_wallet] = true;
    }

    // 移除授权
    function revokePolicyAccess(string memory _policyNumber, address _wallet) external onlyOwner(_policyNumber) {
        delete _policyAuthorized[_policyNumber][_wallet];
    }
    function isAuthorized(string memory _policyNumber, address _wallet) public view returns (bool) {
    return _policyAuthorized[_policyNumber][_wallet];
}

    // 取得所有保單數量
    function getPolicyCount() public view returns (uint) {
        return policyNumbers.length;
    }
}