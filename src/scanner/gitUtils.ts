export function isGitHubUrl(target: string): boolean {
  if (/^https?:\/\/(www\.)?github\.com\//i.test(target)) return true;
  if (/^github\.com\//i.test(target)) return true;
  if (/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(target) && !target.includes('\\')) return true;
  return false;
}

export function normalizeGitHubUrl(target: string): string {
  let url = target.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = `https://github.com/${url.replace(/^github\.com\//i, '')}`;
  }
  if (!url.endsWith('.git')) {
    url += '.git';
  }
  return url;
}
