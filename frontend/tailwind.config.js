/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    "../yads/api/templates/**/*.html",
    "./yads/api/templates/**/*.html",
    "../yads/api/routers/**/*.py",
  ],
  theme: {
    extend: {
      colors: {
        gray: {
          900: "#111827",
          800: "#1f2937",
          700: "#374151",
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
  safelist: [
    // Force generation of these classes for documentation
    { pattern: /prose-h[1-4]:text-orange-\d+/ },
    { pattern: /border-orange-\d+\/\d+/ },
    'text-orange-500',
    'text-orange-400',
    'text-orange-300',
    'prose-h1:text-5xl',
    'prose-h1:mt-16', 
    'prose-h2:mt-24',
  ],
}
