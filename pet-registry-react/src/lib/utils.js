import { clsx } from "clsx";
import { twMerge } from "tailwind-merge"

export function cn(...inputs) {
  return twMerge(clsx(inputs));
}

export function calculateAgeFromDob(dob) {
  if (!dob) return null
  const birth = new Date(dob)
  if (isNaN(birth)) return null
  const now = new Date()
  let years = now.getFullYear() - birth.getFullYear()
  let months = now.getMonth() - birth.getMonth()
  if (now.getDate() < birth.getDate()) months--
  if (months < 0) {
    years--
    months += 12
  }
  return { years, months }
}

export function formatAge({ years, months }) {
  if (years == null || months == null) return '—'
  if (years <= 0 && months <= 0) return '0 months'
  if (years <= 0) return `${months} month${months === 1 ? '' : 's'}`
  if (months <= 0) return `${years} year${years === 1 ? '' : 's'}`
  return `${years} year${years === 1 ? '' : 's'} ${months} mo`
}
