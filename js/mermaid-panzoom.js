function applyPanZoomWhenReady() {
  const maxAttempts = 10;
  let attempts = 0;

  const interval = setInterval(() => {
    const mermaidSvgs = document.querySelectorAll(".mermaid > svg");

    if (mermaidSvgs.length > 0 || attempts >= maxAttempts) {
      clearInterval(interval);

      mermaidSvgs.forEach((svg) => {
        if (svg.getAttribute("data-panzoom-initialized")) return;

        svg.setAttribute("data-panzoom-initialized", "true");

        // Forzar ancho y alto al SVG para evitar que colapse
        svg.removeAttribute("width");
        svg.removeAttribute("height");
        svg.style.width = "100%";
        svg.style.height = "100%";

        const parent = svg.parentElement;
        if (parent) {
          parent.style.display = "block";
          parent.style.width = "100%";
          parent.style.height = "600px"; // Altura fija para evitar colapso (ajustable)
          parent.style.overflow = "hidden";
        }

        svgPanZoom(svg, {
          zoomEnabled: true,
          controlIconsEnabled: true,
          fit: true,
          center: true
        });
      });
    }

    attempts += 1;
  }, 300);
}

document.addEventListener("DOMContentLoaded", applyPanZoomWhenReady);
window.addEventListener("hashchange", () => setTimeout(applyPanZoomWhenReady, 300));
