import { useEffect, useState, useRef } from "react";

/**
 * Text that types out character by character, like a terminal.
 * When the text changes, it types the new value from scratch.
 */
export default function TypingText({
  text,
  speed = 20,
  className = "",
  cursor = true,
}: {
  text: string;
  speed?: number;
  className?: string;
  cursor?: boolean;
}) {
  const [displayed, setDisplayed] = useState("");
  const [showCursor, setShowCursor] = useState(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | undefined>(undefined);
  const prevText = useRef("");

  useEffect(() => {
    if (text === prevText.current) return;
    prevText.current = text;

    let i = 0;
    setDisplayed("");

    intervalRef.current = setInterval(() => {
      if (i < text.length) {
        setDisplayed(text.slice(0, i + 1));
        i++;
      } else {
        clearInterval(intervalRef.current);
      }
    }, speed);

    return () => clearInterval(intervalRef.current);
  }, [text, speed]);

  // Blink cursor
  useEffect(() => {
    if (!cursor) return;
    const blink = setInterval(() => setShowCursor((v) => !v), 530);
    return () => clearInterval(blink);
  }, [cursor]);

  return (
    <span className={className}>
      {displayed}
      {cursor && (
        <span
          className={`inline-block w-[2px] h-[1em] ml-0.5 align-text-bottom bg-accent-primary transition-opacity ${
            showCursor ? "opacity-100" : "opacity-0"
          }`}
        />
      )}
    </span>
  );
}
