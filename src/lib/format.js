/** Small text formatters shared by the pages. */
const AGO = [[60, 's'], [3600, 'min'], [86400, 'h'], [86400 * 30, 'd']];

/** "12 min ago", falling back to the date after a month. */
export const ago = (ms) => {
  const sec = Math.max(0, (Date.now() - ms) / 1000);
  if (sec < 45) return 'just now';
  let div = 1;
  for (const [lim, u] of AGO) { if (sec < lim) return `${Math.floor(sec / div)} ${u} ago`; div = lim; }
  return new Date(ms).toLocaleDateString();
};

export const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
