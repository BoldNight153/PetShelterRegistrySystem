const plugin = require('tailwindcss/plugin')

module.exports = {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}'
  ],
  theme: {
    extend: {
      colors: {
        sidebar: 'var(--sidebar)',
        'sidebar-foreground': 'var(--sidebar-foreground)',
        'sidebar-border': 'var(--sidebar-border)',
        'sidebar-accent': 'var(--sidebar-accent)',
        'sidebar-accent-foreground': 'var(--sidebar-accent-foreground)'
      },
      spacing: {
        'sidebar-width': '16rem',
      }
    }
  },
  plugins: [
    require('tailwindcss-animate'),
    plugin(function({ addUtilities }) {
      addUtilities({
        '.h-svh': { height: '100svh' },
        '.min-h-svh': { 'min-height': '100svh' }
      })
    })
  ]
};
