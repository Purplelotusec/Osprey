/**
 * Terminal output formatting utilities for vulnerability reports
 */

export const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
};

export const symbols = {
  success: "✓",
  error: "✗",
  warning: "⚠",
  info: "ℹ",
  bullet: "•",
};

export function colorize(text: string, color: keyof typeof colors): string {
  return `${colors[color]}${text}${colors.reset}`;
}

export function bold(text: string): string {
  return `${colors.bright}${text}${colors.reset}`;
}

export function dim(text: string): string {
  return `${colors.dim}${text}${colors.reset}`;
}

export function success(text: string): string {
  return colorize(`${symbols.success} ${text}`, "green");
}

export function error(text: string): string {
  return colorize(`${symbols.error} ${text}`, "red");
}

export function warning(text: string): string {
  return colorize(`${symbols.warning} ${text}`, "yellow");
}

export function info(text: string): string {
  return colorize(`${symbols.info} ${text}`, "blue");
}

export function section(title: string): string {
  return `\n${bold(title)}\n${"─".repeat(Math.min(title.length, 80))}\n`;
}

export function formatTable(rows: string[][], options?: { indent?: number }): string {
  const indent = " ".repeat(options?.indent ?? 0);
  if (rows.length === 0) return "";

  const columnCount = Math.max(...rows.map((row) => row.length));
  const columnWidths: number[] = Array(columnCount).fill(0);

  // Calculate column widths (accounting for ANSI codes)
  for (const row of rows) {
    for (let i = 0; i < row.length; i++) {
      const visibleLength = stripAnsi(row[i] ?? "").length;
      columnWidths[i] = Math.max(columnWidths[i] ?? 0, visibleLength);
    }
  }

  // Format rows
  return rows
    .map((row) => {
      const cells = row.map((cell, i) => {
        const visibleLength = stripAnsi(cell).length;
        const padding = " ".repeat((columnWidths[i] ?? 0) - visibleLength);
        return cell + padding;
      });
      return indent + cells.join("  ");
    })
    .join("\n");
}

function stripAnsi(str: string): string {
  return str.replace(/\x1b\[[0-9;]*m/g, "");
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)}MB`;
}
