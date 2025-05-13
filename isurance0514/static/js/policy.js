document.querySelectorAll('.selectPolicy').forEach(button => {
    button.addEventListener('click', (e) => {
        const policyId = e.target.dataset.policyId;
        alert(`已選擇保單 ID: ${policyId}`);
    });
});
