export function isValidPastDate(iso) {
  try {
    const d = new Date(iso)
    return !Number.isNaN(d.getTime()) && d <= new Date()
  } catch (e) {
    return false
  }
}
