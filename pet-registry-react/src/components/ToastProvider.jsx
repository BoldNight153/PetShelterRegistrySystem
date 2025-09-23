import React from 'react'
import ToastUIProvider, { useToastUI } from './ui/toast'

export function ToastProvider({ children }) {
  return <ToastUIProvider>{children}</ToastUIProvider>
}

export function useToast() {
  const { push } = useToastUI()
  return {
    showToast: ({ message, type = 'info', title, duration }) => push({ message, type, title, duration }),
    removeToast: (id) => null,
  }
}

export default ToastProvider
