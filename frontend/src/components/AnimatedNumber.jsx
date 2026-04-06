import useAnimatedNumber from "../hooks/useAnimatedNumber";

export default function AnimatedNumber({
  target,
  duration = 1000,
  decimals = 0,
  enabled = true,
  startValue = 0,
  prefix = "",
  suffix = "",
}) {
  const value = useAnimatedNumber(target, {
    duration,
    decimals,
    enabled,
    startValue,
  });

  const formatted =
    decimals > 0 ? value.toFixed(decimals) : String(Math.round(value));

  return (
    <>
      {prefix}
      {formatted}
      {suffix}
    </>
  );
}
