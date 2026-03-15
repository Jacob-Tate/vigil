import { useEffect, useRef } from "react";
import { Diff2HtmlUI } from "diff2html/lib/ui/js/diff2html-ui-base";
import { ColorSchemeType } from "diff2html/lib/types";
import "diff2html/bundles/css/diff2html.min.css";
import { useTheme } from "../hooks/useTheme";

interface Props {
  diffContent: string;
}

export default function DiffPanel({ diffContent }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const { theme } = useTheme();

  useEffect(() => {
    if (!containerRef.current || !diffContent) return;

    const diff2htmlUi = new Diff2HtmlUI(containerRef.current, diffContent, {
      drawFileList: false,
      matching: "lines",
      outputFormat: "side-by-side",
      highlight: false,
      renderNothingWhenEmpty: false,
      colorScheme: theme === "dark" ? ColorSchemeType.DARK : ColorSchemeType.LIGHT,
    });
    diff2htmlUi.draw();
  }, [diffContent, theme]);

  if (!diffContent) {
    return <p className="text-gray-400 dark:text-gray-500 text-sm text-center py-8">No diff content available.</p>;
  }

  return (
    <div
      ref={containerRef}
      className="text-sm overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700"
    />
  );
}
