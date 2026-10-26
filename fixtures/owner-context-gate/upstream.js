export function serializeEnvelope(payload, attachment) {
  const totalLength = payload.reduce((sum, item) => sum + item.length, 0)
  return JSON.stringify({ attachment, payloadLength: totalLength })
}
