document.addEventListener("DOMContentLoaded", function () {
  fetch("sidebar.html")
    .then((res) => res.text())
    .then((data) => {
      document.getElementById("sidebar-container").innerHTML = data;

      // 等 sidebar 載入後，綁定 toggleSidebar 功能
      document.querySelector(".toggle-btn")?.addEventListener("click", function () {
        const sidebar = document.querySelector(".sidebar");
        const container = document.querySelector(".container");
        if (sidebar && container) {
          sidebar.classList.toggle("collapsed");
          container.classList.toggle("expanded");
        }
      });
    });
});


