export function replaceWords(words, startIndex) {
  const totalLength = words.reduce((sum, word) => sum + word.length, 0)
  return { totalLength, words: words.slice(startIndex) }
}
