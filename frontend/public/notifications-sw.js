self.addEventListener('install', () => {
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim())
})

self.addEventListener('push', (event) => {
  let title = 'Pet Shelter alerts'
  let body = 'You have a new notification'
  let data
  try {
    data = event.data?.json()
    title = data?.title ?? title
    body = data?.body ?? body
  } catch (err) {
    // ignore malformed payloads
  }
  const notificationOptions = {
    body,
    data,
    icon: '/images/icon-192.png',
    badge: '/images/icon-72.png',
  }
  event.waitUntil(self.registration.showNotification(title, notificationOptions))
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  const targetUrl = event.notification?.data?.url || '/'
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) {
          client.postMessage({ type: 'notification-clicked', payload: event.notification?.data || {} })
          return client.focus()
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl)
      }
      return undefined
    }),
  )
})
