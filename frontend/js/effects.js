/**
 * CyberLens Interactive Effects Engine:
 * - Fluid Optical Reticle Cursor with Target Lock-On
 * - Cinematic Lens Calibration Intro Sequence
 */

export const EffectsEngine = {
  /**
   * Initialize custom optical cursor
   */
  initCursor() {
    // Only initialize on devices with precise pointer (not touch)
    if (window.matchMedia("(hover: none) and (pointer: coarse)").matches) {
      return;
    }

    const dot = document.createElement("div");
    dot.className = "cyber-cursor-dot";

    const reticle = document.createElement("div");
    reticle.className = "cyber-cursor-reticle";

    document.body.appendChild(dot);
    document.body.appendChild(reticle);

    let mouseX = -100;
    let mouseY = -100;
    let reticleX = -100;
    let reticleY = -100;

    window.addEventListener("mousemove", (e) => {
      mouseX = e.clientX;
      mouseY = e.clientY;

      dot.style.transform = `translate3d(${mouseX}px, ${mouseY}px, 0) translate(-50%, -50%)`;
    });

    // Smooth fluid interpolation for the outer reticle ring
    function animateCursor() {
      reticleX += (mouseX - reticleX) * 0.18;
      reticleY += (mouseY - reticleY) * 0.18;

      reticle.style.transform = `translate3d(${reticleX}px, ${reticleY}px, 0) translate(-50%, -50%)`;
      requestAnimationFrame(animateCursor);
    }
    requestAnimationFrame(animateCursor);

    // Interactive Hover Lock-On
    const interactiveSelectors = "a, button, input, select, .sample-chip, .btn-secondary, tr";

    document.addEventListener("mouseover", (e) => {
      if (e.target.closest(interactiveSelectors)) {
        reticle.classList.add("active-target");
      }
    });

    document.addEventListener("mouseout", (e) => {
      if (e.target.closest(interactiveSelectors)) {
        reticle.classList.remove("active-target");
      }
    });

    // Hide when mouse leaves viewport
    document.addEventListener("mouseleave", () => {
      dot.style.opacity = "0";
      reticle.style.opacity = "0";
    });

    document.addEventListener("mouseenter", () => {
      dot.style.opacity = "1";
      reticle.style.opacity = "1";
    });
  },

  /**
   * Initialize Cinematic Calibration Splash Screen
   */
  initIntroSequence() {
    const splash = document.getElementById("cinematicSplash");
    if (!splash) return;

    // Check if intro was already played in this browser session
    const hasPlayed = sessionStorage.getItem("cyberlens_intro_played");
    if (hasPlayed) {
      splash.remove();
      return;
    }

    // Dismiss function
    const dismissSplash = () => {
      if (splash.classList.contains("hidden")) return;
      splash.classList.add("hidden");
      sessionStorage.setItem("cyberlens_intro_played", "true");
      setTimeout(() => splash.remove(), 700);
    };

    // Auto dismiss after 1.7 seconds of calibration
    setTimeout(dismissSplash, 1750);

    // Instant skip on click or key press
    splash.addEventListener("click", dismissSplash);
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape" || e.key === " " || e.key === "Enter") {
        dismissSplash();
      }
    }, { once: true });
  },
};
