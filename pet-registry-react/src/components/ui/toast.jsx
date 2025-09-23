import React, { createContext, useContext, useState, useCallback } from 'react'

const ToastUIContext = createContext(null)

export function ToastUIProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const push = useCallback((toast) => {
    const id = Date.now() + Math.random()
    setToasts((t) => [...t, { id, ...toast }])
    if (!toast.duration || toast.duration > 0) {
      setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), toast.duration ?? 3000)
    }
    return id
  }, [])

  const remove = useCallback((id) => setToasts((t) => t.filter((x) => x.id !== id)), [])

  return (
    <ToastUIContext.Provider value={{ push, remove }}>
      {children}
      <div className="fixed top-6 right-6 z-50 flex flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} className={`rounded-md px-4 py-2 shadow text-white ${t.type === 'error' ? 'bg-red-600' : 'bg-green-600'}`}>
            {t.title && <div className="font-semibold">{t.title}</div>}
            <div>{t.message}</div>
          </div>
        ))}
      </div>
    </ToastUIContext.Provider>
  )
}

export function useToastUI() {
  const ctx = useContext(ToastUIContext)
  if (!ctx) throw new Error('useToastUI must be used within a ToastUIProvider')
  return ctx
}

export default ToastUIProvider
