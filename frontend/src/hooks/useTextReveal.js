import { useEffect, useState } from "react";

export default function useTextReveal(
  text,
  { enabled = true, msPerChar = 24, initialDelay = 0 } = {},
) {
  const finalText = String(text ?? "");
  const [visibleText, setVisibleText] = useState(enabled ? "" : finalText);

  useEffect(() => {
    const reducedMotion =
      typeof window !== "undefined" &&
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (!enabled || reducedMotion) {
      setVisibleText(finalText);
      return undefined;
    }

    setVisibleText("");

    if (!finalText.length) {
      return undefined;
    }

    let index = 0;
    let intervalId;

    const delayId = window.setTimeout(
      () => {
        intervalId = window.setInterval(
          () => {
            index += 1;
            setVisibleText(finalText.slice(0, index));

            if (index >= finalText.length) {
              window.clearInterval(intervalId);
            }
          },
          Math.max(10, msPerChar),
        );
      },
      Math.max(0, initialDelay),
    );

    return () => {
      window.clearTimeout(delayId);
      if (intervalId) {
        window.clearInterval(intervalId);
      }
    };
  }, [enabled, finalText, msPerChar, initialDelay]);

  return visibleText;
}
