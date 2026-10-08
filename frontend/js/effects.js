/**
 * CyberLens Interactive Effects Engine:
 * - Cinematic Lens Calibration with Expanding Outer Lines & Aperture Reveal
 * - Executes on every refresh
 */

export const EffectsEngine = {
  /**
   * Initialize Cinematic Calibration Splash Screen with Spreading Aperture Reveal
   */
  initIntroSequence() {
    const splash = document.getElementById("cinematicSplash");
    if (!splash) return;

    let isDismissing = false;

    // Aperture Expansion & Project Reveal Transition
    const triggerReveal = () => {
      if (isDismissing) return;
      isDismissing = true;

      // 1. Trigger the dramatic outer lines expansion / aperture burst
      splash.classList.add("revealing");

      // 2. Remove after the aperture expansion finishes
      setTimeout(() => {
        splash.classList.add("hidden");
        setTimeout(() => splash.remove(), 400);
      }, 750);
    };

    // Auto trigger the aperture expansion after calibration completes (1.4s)
    const timer = setTimeout(triggerReveal, 1400);

    // Instant trigger on click or keypress
    splash.addEventListener("click", () => {
      clearTimeout(timer);
      triggerReveal();
    });

    window.addEventListener(
      "keydown",
      (e) => {
        if (e.key === "Escape" || e.key === " " || e.key === "Enter") {
          clearTimeout(timer);
          triggerReveal();
        }
      },
      { once: true }
    );
  },
};
