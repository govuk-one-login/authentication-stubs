export function truncate(value: string): string {
  if (value.length <= 10) {
    return "obfuscated";
  } else {
    return `${value.slice(0, 3)}...${value.slice(-3)}`;
  }
}
