export function isValidPastDate(iso) {
  if (!iso) return false
  const d = new Date(iso)
  return !isNaN(d.getTime()) && d <= new Date()
}

export default { isValidPastDate }
