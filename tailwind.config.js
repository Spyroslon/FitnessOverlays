// tailwind.config.js
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './static/html/**/*.html',
    './static/js/**/*.js'
  ],
  theme: {
    extend: {
      // --- Add your customizations here ---
      colors: {
        'strava-orange': '#fc4c02',
        'strava-dark-orange': '#e34402',
        'strava-gray': '#666666',
        'strava-text': '#242428',
      },
      fontFamily: {
        // This overrides the default sans-serif font stack
        // If you only want to ADD Roboto, you might need a different approach,
        // but usually, setting the default 'sans' is what you want.
        sans: ['Roboto', 'sans-serif'],
      },
      keyframes: { // You can also move keyframes/animations here from index.html
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        pulseOpacity: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: .5 },
        }
      },
      animation: { // And animations
        fadeIn: 'fadeIn 0.5s ease-out forwards',
        pulseOpacity: 'pulseOpacity 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      }
      // --- End customizations ---
    },
  },
  plugins: [],
}