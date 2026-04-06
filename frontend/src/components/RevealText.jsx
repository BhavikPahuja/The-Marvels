import useTextReveal from "../hooks/useTextReveal";

export default function RevealText({
  as: Tag = "span",
  text,
  className,
  msPerChar = 24,
  initialDelay = 0,
  enabled = true,
}) {
  const revealed = useTextReveal(text, {
    enabled,
    msPerChar,
    initialDelay,
  });

  return <Tag className={className}>{revealed}</Tag>;
}
