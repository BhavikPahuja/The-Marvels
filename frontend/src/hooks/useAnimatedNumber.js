import { useEffect, useState } from "react";

function easeOutCubic(t) {
  return 1 - (1 - t) ** 3;
}

export default function useAnimatedNumber(
  target,
  { duration = 1000, decimals = 0, enabled = true, startValue = 0 } = {},
) {
  const numericTarget = Number.isFinite(Number(target)) ? Number(target) : 0;
  const safeDuration = Math.max(120, Number(duration) || 1000);
  const precision = Math.max(0, Number(decimals) || 0);

  const [value, setValue] = useState(enabled ? startValue : numericTarget);

  useEffect(() => {
    if (!enabled) {
      setValue(numericTarget);
      return undefined;
    }

    let frameId;
    const start = performance.now();

    const tick = (now) => {
      const elapsed = now - start;
      const progress = Math.min(1, elapsed / safeDuration);
      const eased = easeOutCubic(progress);
      const raw = startValue + (numericTarget - startValue) * eased;
      const factor = 10 ** precision;
      setValue(Math.round(raw * factor) / factor);

      if (progress < 1) {
        frameId = window.requestAnimationFrame(tick);
      }
    };

    frameId = window.requestAnimationFrame(tick);

    return () => {
      if (frameId) {
        window.cancelAnimationFrame(frameId);
      }
    };
  }, [enabled, numericTarget, safeDuration, precision, startValue]);

  return value;
}
