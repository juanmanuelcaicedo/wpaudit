(function () {
  document.documentElement.classList.add("js");
  var findings = Array.prototype.slice.call(document.querySelectorAll(".finding"));
  var chips = Array.prototype.slice.call(document.querySelectorAll(".chip"));
  var search = document.getElementById("q");
  var shown = document.getElementById("shown");
  var empty = document.getElementById("empty");
  var active = "all";

  function apply() {
    var query = search ? search.value.trim().toLowerCase() : "";
    var count = 0;
    findings.forEach(function (f) {
      var match = (active === "all" || f.dataset.sev === active) && f.textContent.toLowerCase().indexOf(query) !== -1;
      f.hidden = !match;
      if (match) count++;
    });
    if (shown) shown.textContent = "Mostrando " + count + " de " + findings.length + " hallazgos";
    if (empty) empty.style.display = count ? "none" : "block";
  }

  chips.forEach(function (chip) {
    chip.addEventListener("click", function () {
      active = chip.dataset.sev;
      chips.forEach(function (c) { c.setAttribute("aria-pressed", String(c === chip)); });
      apply();
    });
  });
  if (search) search.addEventListener("input", apply);

  function setAll(open) { findings.forEach(function (f) { f.open = open; }); }
  var expand = document.getElementById("expand");
  var collapse = document.getElementById("collapse");
  if (expand) expand.addEventListener("click", function () { setAll(true); });
  if (collapse) collapse.addEventListener("click", function () { setAll(false); });

  var wasOpen = [];
  window.addEventListener("beforeprint", function () {
    wasOpen = findings.map(function (f) { return f.open; });
    findings.forEach(function (f) { f.hidden = false; f.open = true; });
  });
  window.addEventListener("afterprint", function () {
    findings.forEach(function (f, i) { f.open = wasOpen[i]; });
    apply();
  });

  document.querySelectorAll(".copy").forEach(function (button) {
    button.addEventListener("click", function () {
      var code = button.parentNode.querySelector("pre").textContent;
      function done() {
        button.textContent = "Copiado";
        setTimeout(function () { button.textContent = "Copiar"; }, 1500);
      }
      if (navigator.clipboard) {
        navigator.clipboard.writeText(code).then(done, function () { button.textContent = "Selecciona y copia"; });
      } else {
        button.textContent = "Selecciona y copia";
      }
    });
  });

  var links = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
  if (links.length && "IntersectionObserver" in window) {
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          links.forEach(function (l) { l.classList.toggle("on", l.getAttribute("href") === "#" + entry.target.id); });
        }
      });
    }, { rootMargin: "-20% 0px -70% 0px" });
    document.querySelectorAll("section[id]").forEach(function (s) { observer.observe(s); });
  }
  apply();
})();
