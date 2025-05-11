document.getElementById('language-select').addEventListener('change', function() {
    alert("已切換語言至：" + this.options[this.selectedIndex].text);
});
