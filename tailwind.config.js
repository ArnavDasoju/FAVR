/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/renderer/**/*.{js,ts,jsx,tsx,html}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'monospace'],
        display: ['Fraunces', 'Inter', 'serif']
      },
      colors: {
        // CREAM-primary palette.
        // surface-950 = lightest cream (used as main bg by existing code).
        // surface-50  = deepest sage (used as darkest accents).
        // The scale is inverted vs a dark theme — this means every existing
        // `bg-surface-950` / `bg-surface-900` / `bg-surface-800` read as
        // progressively-darker cream cards and the UI is light by default.
        surface: {
          DEFAULT: '#f7f1df',
          950: '#f8f2e1',   // main bg (lightest cream)
          900: '#f2ead3',   // card bg (soft cream)
          800: '#e9dfc0',   // hover / borders (parchment)
          700: '#d9cba6',   // muted cream
          600: '#b9b28c',   // dusty khaki
          500: '#8a8d6e',   // mid olive
          400: '#5e6c55',   // muted sage text
          300: '#4a5841',   // deep sage text
          200: '#384432',   // darker sage
          100: '#273024',   // near-black moss (dark text)
          50:  '#1a2019'    // darkest
        },
        sage: {
          50:  '#f2f6ed',
          100: '#e1ebd6',
          200: '#c4d8b1',
          300: '#a1c187',
          400: '#82a968',
          500: '#6a8f54',   // primary sage accent
          600: '#527141',
          700: '#405935',
          800: '#35472e',
          900: '#2b3a27'
        },
        cream: {
          50:  '#fcf8ed',
          100: '#f8f2e1',
          200: '#f2ead3',
          300: '#e9dfc0',
          400: '#d9cba6'
        }
      },
      borderRadius: {
        card: '14px',
        btn: '10px',
        input: '8px'
      },
      boxShadow: {
        'sage-glow':  '0 0 24px -4px rgba(106,143,84,0.35)',
        'cream-soft': '0 14px 36px -16px rgba(64,89,53,0.25)',
        'inner-warm': 'inset 0 1px 0 0 rgba(255,255,255,0.6)'
      },
      backgroundImage: {
        'sage-gradient':   'linear-gradient(135deg,#82a968 0%,#405935 100%)',
        'cream-gradient':  'linear-gradient(135deg,#fcf8ed 0%,#e9dfc0 100%)',
        'parchment':       'radial-gradient(ellipse at top, #fcf8ed 0%, #f2ead3 70%)'
      }
    }
  },
  plugins: []
}
