// tailwind.config.js
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './static/html/**/*.html',   // ✅ HTML templates
    './templates/**/*.html',     // ✅ HTML templates
    './static/js/**/*.js',       // ✅ JS files
    './extras/**/*.html',        // 🆕 HTML in extras
    './*.html',                  // 🆕 fallback for root-level HTML if needed
    'node_modules/flowbite/**/*.js'
  ],
  theme: {
    extend: {
      // --- Add your customizations here ---
      colors: {
        'fitness-gray': '#4b5563', // Using the same color value as gray-600
        'fitness-dark-gray': '#030712', // Using the same color value as gray-950
        'fitness-light-gray': '#d1d5db', // Using the same color value as gray-300
        'fitness-green': '#16a34a',  // Using the same color value as green-600
        'fitness-dark-green': '#14532d', // Using the same color value as green-800
        'fitness-light-green': '#86efac', // Using the same color value as green-300
        'fitness-orange': '#ea580c', // Using the same color value as orange-600
      },
      fontFamily: {
        sans: ['Roboto', 'sans-serif'],
        poppins: ['Poppins', 'sans-serif'],
        lato: ['Lato', 'sans-serif'],
        oswald: ['Oswald', 'sans-serif'],
        lora: ['Lora', 'serif'],
        'special-elite': ['Special Elite', 'cursive']
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
  variants: {
    extend: {
      backgroundColor: ['aria-current'], // optional if you're using JIT
    },
  },
  plugins: [
    require('flowbite/plugin')
  ],
}